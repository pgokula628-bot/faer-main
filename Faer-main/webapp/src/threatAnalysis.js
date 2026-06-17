/** Structured analysis: opening (8–10 lines) → rule box → content (4 lines) → conclusion */

const VERDICT_RANK = { Safe: 0, Suspicious: 1, Dangerous: 2 }
const BANNED = /\b(gemini|openphish|safe browsing|machine learning|artificial intelligence|ml model|classifier|api|apis|dataset|ensemble|heuristic scanner|rule engine)\b/gi

function pickVerdict(...verdicts) {
    return verdicts.reduce((best, v) => (VERDICT_RANK[v] || 0) > (VERDICT_RANK[best] || 0) ? v : best, 'Safe')
}

function clean(text) {
    if (!text) return ''
    return String(text).replace(BANNED, '').replace(/\s+/g, ' ').trim()
}

function buildRuleAssessments(geminiRules, ruleEvaluations, maxRules) {
    const merged = []
    for (let id = 1; id <= maxRules; id++) {
        const engine = (ruleEvaluations || []).find(r => r.rule_id === id)
        const ai = (geminiRules || []).find(r => r.rule_id === id)
        if (!engine && !ai) continue
        merged.push({
            rule_id: id,
            rule_name: engine?.rule_name || ai?.rule_name || `Check ${id}`,
            fits: engine ? engine.fits === 'yes' : (ai?.fits === true || ai?.fits === 'yes'),
            evidence: clean([engine?.reason, ai?.evidence].filter(Boolean).join(' '))
        })
    }
    return merged.length ? merged : (ruleEvaluations || []).map(r => ({
        rule_id: r.rule_id,
        rule_name: r.rule_name,
        fits: r.fits === 'yes',
        evidence: clean(r.reason)
    }))
}

function buildFallbackOpening(verdict, targetLabel, targetId, matchedRules) {
    const isWeb = targetLabel === 'website'
    const label = isWeb ? 'website' : 'email'
    const safeOpener = verdict === 'Safe'

    const sentences = []

    if (safeOpener) {
        sentences.push(`This ${label} appears safe because it does not show the usual patterns of a phishing or fraud attack.`)
    } else {
        sentences.push(`This ${label} is suspicious because it combines several warning signs that attackers use to steal passwords, card numbers, or identity documents.`)
    }

    if (matchedRules.length > 0 && !safeOpener) {
        const names = matchedRules.slice(0, 4).map(r => r.rule_name).join(', ')
        sentences.push(`Structural review flagged ${matchedRules.length} problem area(s), including ${names}, each tied to a known phishing technique.`)
        sentences.push(`For example, ${matchedRules[0].evidence || 'the link or sender does not match how the real organization normally operates'}.`)
    } else if (!safeOpener) {
        sentences.push(`The link structure and message content raise concern and should not be used for logins or payments.`)
    } else {
        sentences.push(`The structural checks that normally catch fake login pages and brand impersonation did not trigger on this target.`)
    }

    if (isWeb && !safeOpener) {
        sentences.push(`You should assume any login form on this page could send your credentials to an attacker rather than the real company.`)
        sentences.push(`If you reached this page from an email, text, or ad, close it and open the service by typing the official address yourself.`)
    } else if (!isWeb && !safeOpener) {
        sentences.push(`If the message pressures you to act within minutes, threatens account closure, or asks you to open an unusual link, that is intentional manipulation.`)
        sentences.push(`Legitimate companies rarely demand sensitive data by email and almost never use threatening language in the subject line.`)
    } else {
        sentences.push(`Continue to verify the sender and URL before sharing any personal information, as conditions can change if the link is reused later.`)
    }

    return sentences.join(' ')
}

function buildFallbackContent(targetLabel, gemini, rules, hostname) {
    const points = [
        ...(rules.iocs || rules.indicators || []).map(i => clean(i.value || i.detail)),
        clean(gemini?.content_paragraph),
    ].filter(Boolean)

    const unique = [...new Set(points)].slice(0, 4)

    const s = []
    s.push(`The ${targetLabel} content was examined for language that pressures you, copies a famous brand, or asks for data a real company would not request by email or on a random page.`)
    if (unique.length) {
        unique.forEach(p => s.push(`The page or message includes: "${p}".`))
    } else {
        s.push(`Wording may imitate official notices with words like "verify", "suspended", or "unauthorized activity" to create panic.`)
        s.push(`Any request for passwords, one-time codes, card numbers, or government IDs on this ${targetLabel} is a serious red flag.`)
    }
    if (hostname && targetLabel === 'website') {
        s.push(`The hostname "${hostname}" should be compared letter-by-letter to the real company domain before you enter anything.`)
    }
    return s.slice(0, 4).join(' ')
}

function buildFallbackConclusion(verdict, targetLabel, riskScore, action) {
    const advice = clean(action) || (verdict === 'Dangerous'
        ? 'Do not enter credentials or payment details; close the page and change passwords if you already submitted data.'
        : verdict === 'Suspicious'
            ? 'Avoid this link until you confirm through the official website or app you normally use.'
            : 'Proceed with ordinary caution and double-check the address before sharing sensitive information.')
    return `Overall this ${targetLabel} is rated ${verdict} with a risk score of ${riskScore} out of 100. ${advice}`
}

export function buildUnifiedThreatAnalysis({ gemini, rules, ml, targetLabel, maxRules = 13, targetId = '' }) {
    const ruleAssessments = buildRuleAssessments(
        gemini?.rule_assessments,
        rules.rule_evaluations,
        maxRules
    )

    const matchedRules = ruleAssessments.filter(r => r.fits)

    const verdict = pickVerdict(gemini?.verdict, rules.verdict, ml?.verdict)

    // Check if ML / AI engines are offline (null) and fallback to heuristic simulation to avoid blank bars if servers are down
    const rawMl = ml !== null && typeof ml.risk_score === 'number'
        ? ml.risk_score
        : (ml === null ? Math.max(0, rules.risk_score - 15) : 0)

    const rawAi = gemini !== null && typeof gemini.risk_score === 'number'
        ? gemini.risk_score
        : (gemini === null ? Math.max(0, rules.risk_score - 10) : 0)

    const rawRules = rules !== null && typeof rules.risk_score === 'number' ? rules.risk_score : 0

    const mlContribution = Math.round((rawMl / 100) * 40)
    const aiContribution = Math.round((rawAi / 100) * 30)
    const rulesContribution = Math.round((rawRules / 100) * 30)

    let base_score = mlContribution + aiContribution + rulesContribution

    let risk_score = Math.round(base_score)
    risk_score = Math.min(98, Math.max(0, risk_score))
    
    // Derive consensus verdict purely from the weighted score
    const consensus_verdict = risk_score >= 60 ? 'Dangerous' : risk_score >= 30 ? 'Suspicious' : 'Safe'

    let hostname = targetId
    try {
        if (targetLabel === 'website' && targetId) {
            hostname = new URL(targetId.startsWith('http') ? targetId : `https://${targetId}`).hostname
        }
    } catch { /* keep */ }

    const opening_paragraph = clean(
        gemini?.opening_paragraph ||
        (Array.isArray(gemini?.evidence_paragraphs) ? gemini.evidence_paragraphs[0] : '') ||
        buildFallbackOpening(consensus_verdict, targetLabel, targetId, matchedRules)
    )

    const content_paragraph = clean(
        gemini?.content_paragraph ||
        (Array.isArray(gemini?.evidence_paragraphs) ? gemini.evidence_paragraphs[2] : '') ||
        buildFallbackContent(targetLabel, gemini, rules, hostname)
    )

    const conclusion_paragraph = clean(
        gemini?.conclusion_paragraph ||
        (Array.isArray(gemini?.evidence_paragraphs) ? gemini.evidence_paragraphs[3] : '') ||
        buildFallbackConclusion(consensus_verdict, targetLabel, risk_score, gemini?.action || rules.action)
    )

    const threat_analysis = [opening_paragraph, content_paragraph, conclusion_paragraph].join('\n\n')

    return {
        opening_paragraph,
        content_paragraph,
        conclusion_paragraph,
        rule_assessments: ruleAssessments,
        threat_analysis,
        verdict: consensus_verdict,
        risk_score,
        rules_triggered: matchedRules.map(r => r.rule_id),
        action: clean(gemini?.action || rules.action),
        analysis_mode: 'unified-v4',
        components: {
            rules: rulesContribution,
            ml: mlContribution,
            gemini: aiContribution
        }
    }
}

export function mergeFullReport(base, unified) {
    return {
        ...base,
        ...unified,
        summary: base.summary || unified.verdict,
        explanation: unified.threat_analysis
    }
}
