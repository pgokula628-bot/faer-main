/** Unified report — natural language only (no tool/model names in user output) */

const VERDICT_RANK = { Safe: 0, Suspicious: 1, Dangerous: 2 }
const BANNED_TERMS = /\b(gemini|google gemini|openphish|safe browsing|ml engine|machine learning|random forest|xgboost|naive bayes|phish tank|phishtank|apis?|models?|ensemble|dataset|classifier|hybrid|rule engine)\b/gi

function pickVerdict(...verdicts) {
    return verdicts.reduce((best, v) => (VERDICT_RANK[v] || 0) > (VERDICT_RANK[best] || 0) ? v : best, 'Safe')
}

function sanitizeText(text) {
    if (!text) return ''
    return text.replace(BANNED_TERMS, 'security analysis').replace(/\s+/g, ' ').trim()
}

function buildRuleAssessments(geminiRules, ruleEvaluations, maxRules) {
    const fromEngine = (ruleEvaluations || []).map(r => ({
        rule_id: r.rule_id,
        rule_name: r.rule_name,
        fits: r.fits === 'yes',
        evidence: sanitizeText(r.reason)
    }))

    const fromAi = (geminiRules || []).map(r => ({
        rule_id: r.rule_id,
        rule_name: r.rule_name,
        fits: r.fits === true || r.fits === 'yes',
        evidence: sanitizeText(r.evidence || r.reason || '')
    }))

    const merged = []
    for (let id = 1; id <= maxRules; id++) {
        const engine = fromEngine.find(x => x.rule_id === id)
        const ai = fromAi.find(x => x.rule_id === id)
        const base = engine || ai
        if (!base && !engine && !ai) continue
        merged.push({
            rule_id: id,
            rule_name: (engine || ai)?.rule_name || `Rule ${id}`,
            fits: engine ? engine.fits : (ai ? ai.fits : false),
            evidence: sanitizeText(
                [engine?.evidence, ai?.evidence].filter(Boolean).join(' ') ||
                (engine?.fits ? 'Condition matched for this target.' : 'Condition not met for this target.')
            )
        })
    }
    return merged.length ? merged : fromEngine
}

export function buildUnifiedThreatAnalysis({ gemini, rules, ml, liveIntel, targetLabel, maxRules = 13 }) {
    const ruleAssessments = buildRuleAssessments(
        gemini?.rule_assessments,
        rules.rule_evaluations,
        maxRules
    )

    const whySafe = [
        ...(gemini?.why_safe || []).map(sanitizeText),
        ...(liveIntel && !liveIntel.any_threat ? [sanitizeText(liveIntel.summary)] : []),
        ...ruleAssessments.filter(r => !r.fits && r.rule_id !== maxRules).slice(0, 4).map(r =>
            `Rule ${r.rule_id} does not apply: ${r.evidence}`
        )
    ].filter(Boolean)

    const whyUnsafe = [
        ...(gemini?.why_unsafe || []).map(sanitizeText),
        ...(liveIntel?.any_threat ? [sanitizeText(liveIntel.summary)] : []),
        ...ruleAssessments.filter(r => r.fits).map(r =>
            `Rule ${r.rule_id} (${r.rule_name}) applies: ${r.evidence}`
        ),
        ...(ml?.risk_factors || []).map(sanitizeText)
    ].filter(Boolean)

    const detailedEvidence = [
        ...(gemini?.evidence || []).map(e => ({
            category: sanitizeText(e.category || e.type || 'Finding'),
            finding: sanitizeText(e.finding || e.value || e.detail),
            implication: sanitizeText(e.implication || '')
        })),
        ...(rules.iocs || rules.indicators || []).map(i => ({
            category: sanitizeText(i.type),
            finding: sanitizeText(i.value || i.detail),
            implication: 'Structural or content indicator observed on this target.'
        })),
        ...(liveIntel?.results || []).flatMap(r => {
            const items = []
            if (r.safeBrowsing?.checked) {
                items.push({
                    category: 'Live blocklist (browser-grade)',
                    finding: sanitizeText(r.safeBrowsing.detail),
                    implication: r.safeBrowsing.threat ? 'Listed on an active threat blocklist.' : 'No current blocklist listing.'
                })
            }
            if (r.openPhish?.checked && r.openPhish.threat) {
                items.push({
                    category: 'Active phishing feed',
                    finding: sanitizeText(r.openPhish.detail),
                    implication: 'URL/host appears on a live phishing campaign feed.'
                })
            }
            return items
        })
    ]

    const narrativeParts = []

    if (gemini?.detailed_analysis) {
        narrativeParts.push(sanitizeText(gemini.detailed_analysis))
    } else if (gemini?.explanation) {
        narrativeParts.push(sanitizeText(gemini.explanation))
    }

    if (liveIntel?.summary) {
        narrativeParts.push(sanitizeText(liveIntel.summary))
    }

    if (whyUnsafe.length) {
        narrativeParts.push(
            `This ${targetLabel} is considered unsafe because: ${whyUnsafe.slice(0, 8).join(' ')}`
        )
    }

    if (whySafe.length && (gemini?.verdict === 'Safe' || rules.verdict === 'Safe')) {
        narrativeParts.push(
            `Reasons it may still appear legitimate: ${whySafe.slice(0, 6).join(' ')}`
        )
    }

    const fitsCount = ruleAssessments.filter(r => r.fits && r.rule_id !== maxRules).length
    narrativeParts.push(
        `Security rule review: ${fitsCount} of ${maxRules - 1} threat rules matched. ` +
        ruleAssessments.map(r =>
            `Rule ${r.rule_id} (${r.rule_name}): ${r.fits ? 'FITS' : 'DOES NOT FIT'} — ${r.evidence}`
        ).join(' ')
    )

    const verdict = pickVerdict(gemini?.verdict, rules.verdict, ml?.verdict)
    let risk_score = Math.min(100, Math.round(
        (gemini?.risk_score || 0) * 0.45 +
        (rules.risk_score || 0) * 0.35 +
        (ml?.risk_score || 0) * 0.2 +
        (liveIntel?.risk_boost || 0)
    ))

    if (liveIntel?.any_threat) risk_score = Math.max(risk_score, 70)

    const whySuspicious = verdict !== 'Safe'
        ? sanitizeText(
            whyUnsafe.length
                ? whyUnsafe.slice(0, 5).join(' ')
                : 'Multiple independent checks found elevated phishing or fraud risk.'
        )
        : sanitizeText(
            whySafe.length
                ? whySafe.slice(0, 4).join(' ')
                : 'No critical phishing indicators; connection and reputation checks are clear.'
        )

    return {
        threat_analysis: narrativeParts.filter(Boolean).join('\n\n'),
        why_suspicious: whySuspicious,
        why_safe: whySafe,
        why_unsafe: whyUnsafe,
        rule_assessments: ruleAssessments,
        detailed_evidence: detailedEvidence,
        verdict,
        risk_score,
        indicators: detailedEvidence.map(e => ({
            type: e.category,
            value: e.implication ? `${e.finding} — ${e.implication}` : e.finding
        })),
        rules_triggered: rules.rules_triggered || ruleAssessments.filter(r => r.fits && r.rule_id !== maxRules).map(r => r.rule_id),
        test_row: {
            verdict,
            risk_score,
            indicators_count: detailedEvidence.length,
            rules: (rules.rules_triggered || []).map(r => `R${r}`).join(', ') || 'None'
        }
    }
}

export function mergeFullReport(base, unified) {
    return {
        ...base,
        ...unified,
        summary: base.summary || unified.verdict,
        action: base.action,
        analysis_mode: 'unified-v2'
    }
}
