/** Build 3–4 evidence paragraphs only (no sub-headings, no tool names) */

const VERDICT_RANK = { Safe: 0, Suspicious: 1, Dangerous: 2 }
const BANNED = /\b(gemini|openphish|safe browsing|machine learning|artificial intelligence|ml model|classifier|random forest|xgboost|naive bayes|phish tank|phishtank|api|apis|dataset|datasets|ensemble|heuristic scanner|rule engine|correlating these behavioral)\b/gi

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
            rule_name: engine?.rule_name || ai?.rule_name || `Security check ${id}`,
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

function quoteFact(text) {
    const t = clean(text)
    return t ? ` Specifically, ${t.charAt(0).toLowerCase() + t.slice(1)}` : ''
}

function buildParagraph1(verdict, targetLabel, urlOrSender, liveIntel, matchedRules) {
    const subject = targetLabel === 'website' ? `The website at "${urlOrSender}"` : `The email from "${urlOrSender}"`
    const topRules = matchedRules.slice(0, 3).map(r => r.rule_name.toLowerCase()).join(', ')

    if (verdict === 'Safe') {
        return `${subject} does not show strong signs of phishing or fraud based on current checks. Live reputation data did not place this address on active criminal blocklists, and the structural review found no critical red flags that would normally appear on credential-stealing pages.${quoteFact(liveIntel?.summary)}`
    }

    let opener = `${subject} is ${verdict.toLowerCase()} and should be treated as a potential phishing or fraud attempt. `
    if (liveIntel?.any_threat) {
        opener += `This address appears on live browser-grade threat blocklists that are updated continuously, which is a strong indicator that other users have already reported it as malicious.${quoteFact(liveIntel.summary)} `
    } else {
        opener += `Although it is not on a public blocklist at this moment, multiple independent checks still found serious problems. `
    }
    if (matchedRules.length) {
        opener += `The clearest problems involve ${topRules}, each of which is a known tactic used to steal logins or payment details.`
    }
    return opener
}

function buildParagraph2(targetLabel, matchedRules, clearedRules) {
    const fitsLines = matchedRules.map(r =>
        `the "${r.rule_name}" check applies because ${r.evidence || 'the pattern matches known attack pages'}`
    )
    const clearSample = clearedRules.filter(r => !r.fits).slice(0, 2).map(r =>
        `the "${r.rule_name}" check does not apply${r.evidence ? ` because ${r.evidence}` : ''}`
    )

    let p = `A full rule-by-rule review was performed on this ${targetLabel}. `
    if (fitsLines.length) {
        p += `The following security checks matched: ${fitsLines.join('; ')}. `
    } else {
        p += `None of the major structural phishing checks matched, which lowers—but does not eliminate—concern. `
    }
    if (clearSample.length) {
        p += `For transparency, ${clearSample.join('; ')}. `
    }
    p += `When a check "fits," it means the page or message contains the exact pattern that check was designed to catch (for example, a fake brand name in the link, or language that pressures you to act within minutes).`
    return p
}

function buildParagraph3(targetLabel, gemini, rules, ml, hostname) {
    const contentFindings = (rules.iocs || rules.indicators || []).map(i => clean(i.value || i.detail)).filter(Boolean)
    const geminiPoints = (gemini?.why_unsafe || gemini?.evidence || []).map(e =>
        clean(typeof e === 'string' ? e : `${e.finding || ''} ${e.implication || ''}`)
    ).filter(Boolean)

    const points = [...contentFindings, ...geminiPoints, ...(ml?.risk_factors || []).map(clean)].filter(Boolean)
    const unique = [...new Set(points)].slice(0, 5)

    let p = `Looking at what the ${targetLabel} actually says and asks you to do, `
    if (unique.length) {
        p += `this is suspicious because: ${unique.map((u, i) => `${i === 0 ? '' : ' '}${i > 0 && i === unique.length - 1 ? 'and ' : i > 0 ? 'also, ' : ''}"${u}"`).join('')}. `
    } else if (gemini?.detailed_analysis) {
        p += clean(gemini.detailed_analysis) + ' '
    } else {
        p += `the wording and requests do not match how legitimate organizations normally communicate. `
    }

    if (hostname && targetLabel === 'website') {
        p += `The domain "${hostname}" must be read carefully: attackers often add extra words, hyphens, or misspellings so it looks like a famous company while sending your data elsewhere. `
    }

    p += `Any request to enter a password, card number, government ID, or "verify" an account on a page you reached from an unexpected link is a classic sign that someone is trying to copy a real login screen.`
    return p
}

function buildParagraph4(verdict, targetLabel, action, riskScore) {
    const advice = clean(action) || (verdict === 'Dangerous'
        ? `Do not enter personal or financial information. Close the page, do not click links, and if you already submitted data, change passwords from a different device and contact your bank.`
        : verdict === 'Suspicious'
            ? `Do not use this ${targetLabel} until you confirm it through the official app or website you normally use—type the address yourself instead of following the link.`
            : `You may proceed with normal caution, but always confirm the address bar and sender before sharing sensitive information.`)

    return `Taken together, the evidence supports a ${verdict.toLowerCase()} rating with an overall risk score of ${riskScore} out of 100. ${advice}`
}

export function buildUnifiedThreatAnalysis({ gemini, rules, ml, liveIntel, targetLabel, maxRules = 13, targetId = '' }) {
    const ruleAssessments = buildRuleAssessments(gemini?.rule_assessments, rules.rule_evaluations, maxRules)
    const matchedRules = ruleAssessments.filter(r => r.fits && r.rule_id !== maxRules)
    const clearedRules = ruleAssessments.filter(r => !r.fits)

    const verdict = pickVerdict(gemini?.verdict, rules.verdict, ml?.verdict)
    let risk_score = Math.min(100, Math.round(
        (gemini?.risk_score || 0) * 0.45 +
        (rules.risk_score || 0) * 0.35 +
        (ml?.risk_score || 0) * 0.2 +
        (liveIntel?.risk_boost || 0)
    ))
    if (liveIntel?.any_threat) risk_score = Math.max(risk_score, 70)

    let hostname = targetId
    try {
        if (targetLabel === 'website' && targetId) hostname = new URL(targetId.startsWith('http') ? targetId : `https://${targetId}`).hostname
    } catch { /* keep raw */ }

    // Use Gemini paragraphs if provided (3–4), else build locally
    let paragraphs = []
    if (Array.isArray(gemini?.evidence_paragraphs) && gemini.evidence_paragraphs.length >= 3) {
        paragraphs = gemini.evidence_paragraphs.map(clean).filter(p => p.length > 40).slice(0, 4)
    }

    if (paragraphs.length < 3) {
        paragraphs = [
            buildParagraph1(verdict, targetLabel, targetId || 'this target', liveIntel, matchedRules),
            buildParagraph2(targetLabel, matchedRules, clearedRules),
            buildParagraph3(targetLabel, gemini, rules, ml, hostname),
            buildParagraph4(verdict, targetLabel, gemini?.action || rules.action, risk_score)
        ]
    } else if (paragraphs.length === 3) {
        paragraphs.push(buildParagraph4(verdict, targetLabel, gemini?.action || rules.action, risk_score))
    }

    const threat_analysis = paragraphs.join('\n\n')

    return {
        threat_analysis,
        analysis_paragraphs: paragraphs,
        verdict,
        risk_score,
        rule_assessments: ruleAssessments,
        rules_triggered: matchedRules.map(r => r.rule_id),
        action: clean(gemini?.action || rules.action),
        analysis_mode: 'unified-v3'
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
