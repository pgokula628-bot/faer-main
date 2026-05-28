/** Threat Lens — Heuristic Rule Engine (13 website / 14 email rules only) */

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.club', '.work', '.click', '.link', '.info', '.bid', '.win', '.icu', '.monster', '.cfd', '.sbs']
const TRUSTED_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'netflix.com', 'paypal.com', 'ebay.com', 'whatsapp.com', 'zoom.us', 'outlook.com', 'live.com', 'office.com', 'bing.com', 'yahoo.com', 'adobe.com', 'dropbox.com', 'slack.com', 'notion.so', 'figma.com', 'vercel.app', 'cloudflare.com']
const BRAND_KEYWORDS = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'facebook', 'instagram', 'whatsapp', 'bank', 'chase', 'wells', 'citi', 'hdfc', 'icici', 'hsbc', 'fedex', 'usps', 'dhl', 'irs', 'ebay', 'walmart', 'spotify', 'steam', 'crypto', 'binance', 'coinbase', 'login', 'signin', 'verify', 'secure']
const URGENCY_WORDS = ['urgent', 'immediately', 'suspended', 'blocked', 'locked', 'disabled', 'expired', 'unauthorized', 'compromised', 'final notice', 'act now', 'within 24', 'failure to comply', 'respond immediately']
const SENSITIVE_WORDS = ['social security', 'ssn', 'credit card', 'cvv', 'cvc', 'bank account', 'routing number', 'password', 'otp', 'verification code', 'seed phrase', 'pin number']
const PHISHING_URL_PATTERNS = [/paypa[l1]/i, /amaz[o0]n/i, /g[o0]{2}gle/i, /micros[o0]ft/i, /app[l1]e/i, /faceb[o0]{2}k/i, /netf[l1]ix/i, /[a-z]+-verify/i, /[a-z]+-secure/i, /[a-z]+-login/i]
const FREE_EMAIL = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com', 'icloud.com']

function ruleEval(ruleId, ruleName, applies, reasonYes, reasonNo, scoreImpact = 0) {
    return { rule_id: ruleId, rule_name: ruleName, fits: applies ? 'yes' : 'no', applies, score_impact: applies ? scoreImpact : 0, reason: applies ? reasonYes : reasonNo }
}

export function analyzeWebsite(targetUrl, targetText) {
    const findings = []
    const ruleEvaluations = []
    let score = 0
    const content = (targetText || '').toLowerCase()
    let hostname = '', protocol = ''

    try {
        let normalizedUrl = targetUrl
        if (!targetUrl.startsWith('http') && !targetUrl.startsWith('file:')) {
            normalizedUrl = `https://${targetUrl}`
        }
        const u = new URL(normalizedUrl)
        hostname = u.hostname
        protocol = u.protocol
    } catch { hostname = targetUrl }

    const isTrusted = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))
    const domainBase = hostname.replace(/\.[^.]+$/, '')

    // 1 HTTP vs HTTPS (also flag file:// and localhost as insecure)
    const isInsecureProtocol = protocol === 'http:' || protocol === 'file:' || hostname.includes('localhost') || hostname === '127.0.0.1'
    const r1 = isInsecureProtocol && protocol !== 'https:'
    if (r1) { score += 15; findings.push({ type: 'Rule 1', value: protocol === 'file:' ? 'file:// protocol — local file, no server encryption' : 'HTTP/localhost — no encryption' }) }
    ruleEvaluations.push(ruleEval(1, 'HTTP vs HTTPS', r1, protocol === 'file:' ? 'Local file (file://) with no server encryption (+15)' : 'Uses HTTP or localhost; data not encrypted (+15)', 'Uses HTTPS — encrypted connection', 15))

    // 2 IP as domain
    const r2 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
    if (r2) { score += 25; findings.push({ type: 'Rule 2', value: `IP host ${hostname}` }) }
    ruleEvaluations.push(ruleEval(2, 'IP Address Domain', r2, `Raw IP ${hostname} (+25)`, 'Normal domain name', 25))

    // 3 Suspicious TLD
    const tld = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t))
    const r3 = Boolean(tld)
    if (r3) { score += 15; findings.push({ type: 'Rule 3', value: `Risk TLD ${tld}` }) }
    ruleEvaluations.push(ruleEval(3, 'Suspicious TLD', r3, `TLD ${tld} on blocklist (+15)`, 'TLD not on blocklist', 15))

    // 4 Excessive subdomains
    const subCount = Math.max(0, hostname.split('.').length - 2)
    const r4 = subCount >= 3
    if (r4) { score += 15; findings.push({ type: 'Rule 4', value: `${subCount} subdomains` }) }
    ruleEvaluations.push(ruleEval(4, 'Excessive Subdomains', r4, `${subCount} subdomains (+15)`, `Only ${subCount} subdomain level(s)`, 15))

    // 5 Typosquatting / brand impersonation URL
    const r5 = PHISHING_URL_PATTERNS.some(p => p.test(hostname)) && !isTrusted
    if (r5) { score += 30; findings.push({ type: 'Rule 5', value: 'Brand impersonation in URL' }) }
    ruleEvaluations.push(ruleEval(5, 'Typosquatting / Brand URL', r5, 'URL mimics known brand (+30)', isTrusted ? 'Trusted official domain' : 'No brand spoof in hostname', 30))

    // 6 Letter substitution
    const hasSub = /[a-z]+[0-9]+[a-z]+/i.test(domainBase) || /[0-9]+[a-z]+[0-9]+/i.test(domainBase)
    const norm = domainBase.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    const r6 = hasSub && BRAND_KEYWORDS.some(b => norm.includes(b))
    if (r6) { score += 25; findings.push({ type: 'Rule 6', value: '0→o / 1→l substitution' }) }
    ruleEvaluations.push(ruleEval(6, 'Letter Substitution', r6, `Digits mimic brand in "${domainBase}" (+25)`, 'No brand-like digit substitution', 25))

    // 7 Urgency language
    const urg = URGENCY_WORDS.filter(w => content.includes(w))
    const r7 = urg.length >= 1
    if (urg.length >= 3) { score += 25; findings.push({ type: 'Rule 7', value: urg.slice(0, 3).join(', ') }) }
    else if (r7) { score += 12; findings.push({ type: 'Rule 7', value: urg[0] }) }
    ruleEvaluations.push(ruleEval(7, 'Urgency Language', r7, `${urg.length} urgency phrase(s) (+${urg.length >= 3 ? 25 : 12})`, 'No urgency triggers', urg.length >= 3 ? 25 : 12))

    // 8 Sensitive data
    const sens = SENSITIVE_WORDS.filter(w => content.includes(w))
    const r8 = sens.length >= 1
    if (sens.length >= 2) { score += 30; findings.push({ type: 'Rule 8', value: sens.slice(0, 3).join(', ') }) }
    else if (r8) { score += 15; findings.push({ type: 'Rule 8', value: sens[0] }) }
    ruleEvaluations.push(ruleEval(8, 'Sensitive Data Request', r8, `${sens.length} sensitive term(s) (+${sens.length >= 2 ? 30 : 15})`, 'No sensitive data language', sens.length >= 2 ? 30 : 15))

    // 9 Login form untrusted
    const r9 = content.includes('password') && (content.includes('login') || content.includes('sign in')) && !isTrusted
    if (r9) { score += 20; findings.push({ type: 'Rule 9', value: 'Login form on untrusted domain' }) }
    ruleEvaluations.push(ruleEval(9, 'Login Form Untrusted', r9, 'Password/login form on non-trusted site (+20)', isTrusted ? 'Trusted site login' : 'No login form signals', 20))

    // 10 Brand mismatch
    const brands = BRAND_KEYWORDS.filter(b => content.includes(b) && !hostname.includes(b))
    const r10 = brands.length >= 2 && !isTrusted
    if (r10) { score += 18; findings.push({ type: 'Rule 10', value: brands.slice(0, 3).join(', ') }) }
    ruleEvaluations.push(ruleEval(10, 'Brand Mismatch', r10, `Content brands (${brands.slice(0, 2).join(', ')}) ≠ domain (+18)`, 'Brands align or <2 mentions', 18))

    // 11 Suspicious links in page
    const links = content.match(/https?:\/\/[^\s"'<>]+/gi) || []
    const badLinks = links.filter(l => {
        try {
            const h = new URL(l).hostname
            return !TRUSTED_DOMAINS.some(d => h === d || h.endsWith('.' + d)) && (SUSPICIOUS_TLDS.some(t => h.endsWith(t)) || PHISHING_URL_PATTERNS.some(p => p.test(h)))
        } catch { return true }
    })
    const r11 = badLinks.length > 0
    if (r11) { score += 18; findings.push({ type: 'Rule 11', value: `${badLinks.length} suspicious link(s)` }) }
    ruleEvaluations.push(ruleEval(11, 'Suspicious Page Links', r11, `${badLinks.length} malicious-looking link(s) (+18)`, 'No bad embedded links', 18))

    // 12 @ in URL (credential trick)
    const r12 = targetUrl.includes('@')
    if (r12) { score += 20; findings.push({ type: 'Rule 12', value: '@ symbol in URL' }) }
    ruleEvaluations.push(ruleEval(12, 'URL @ Credential Trick', r12, '@ in URL hides real destination (+20)', 'No @ trick in URL', 20))

    // 13 Trusted whitelist
    const r13 = isTrusted
    if (r13) score = Math.max(0, score - 40)
    ruleEvaluations.push(ruleEval(13, 'Trusted Domain Whitelist', r13, `"${hostname}" trusted (−40 risk)`, `"${hostname}" not on whitelist`, -40))

    // Combo bonus: when 3+ content-based rules (7, 8, 9, 10) all fire, add +15 bonus
    const contentRulesFired = [r7, r8, r9, r10].filter(Boolean).length
    if (contentRulesFired >= 3) { score += 15; findings.push({ type: 'Combo', value: `${contentRulesFired} content rules triggered together (+15)` }) }

    score = Math.min(100, Math.max(0, score))
    const triggered = ruleEvaluations.filter(r => r.applies && r.rule_id !== 13).length
    let verdict = score >= 60 ? 'Dangerous' : score >= 30 ? 'Suspicious' : 'Safe'

    return {
        verdict,
        risk_score: score,
        summary: verdict === 'Dangerous' ? 'High-Risk Phishing Website' : verdict === 'Suspicious' ? 'Potentially Unsafe Website' : 'No Major Threats Detected',
        explanation: triggered ? `${triggered} of 12 threat rules triggered.` : 'All 12 threat rules clear; trusted whitelist applied if applicable.',
        action: verdict === 'Dangerous' ? 'Do not enter credentials. Close the page.' : verdict === 'Suspicious' ? 'Verify URL via official search before continuing.' : 'Proceed with normal caution.',
        iocs: findings,
        indicators: findings.map(f => ({ type: f.type, detail: f.value, severity: f.type.includes('1') || f.type.includes('2') || f.type.includes('5') ? 'high' : 'medium' })),
        rule_evaluations: ruleEvaluations,
        rules_triggered: ruleEvaluations.filter(r => r.applies && r.rule_id !== 13).map(r => r.rule_id)
    }
}

export function analyzeEmail(sender, subject, body) {
    const indicators = []
    const ruleEvaluations = []
    let score = 0
    const s = (sender || '').toLowerCase()
    const sub = (subject || '').toLowerCase()
    const bod = (body || '').toLowerCase()
    const all = `${sub} ${bod}`

    let domain = ''
    const em = s.match(/@([a-z0-9.-]+)/)
    if (em) domain = em[1]
    const trusted = TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d))

    const r1 = PHISHING_URL_PATTERNS.some(p => p.test(domain)) && !trusted
    if (r1) { score += 30; indicators.push({ type: 'Rule 1', detail: 'Spoofed sender domain', severity: 'high' }) }
    ruleEvaluations.push(ruleEval(1, 'Spoofed Sender Domain', r1, `Sender ${domain} mimics brand (+30)`, 'Sender not spoofed', 30))

    const r2 = FREE_EMAIL.includes(domain) && BRAND_KEYWORDS.some(b => s.includes(b) || sub.includes(b))
    if (r2) { score += 20; indicators.push({ type: 'Rule 2', detail: 'Free email + brand claim', severity: 'high' }) }
    ruleEvaluations.push(ruleEval(2, 'Free Email Impersonation', r2, `Free ${domain} claims organization (+20)`, 'Not free-email impersonation', 20))

    const domBase = domain.split('.')[0] || ''
    const suspTld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t))
    const r3 = Boolean(domain && ((domBase.match(/-/g) || []).length >= 2 || suspTld))
    if (r3) { score += 12; indicators.push({ type: 'Rule 3', detail: 'Suspicious sender structure', severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(3, 'Suspicious Sender Domain', r3, 'Hyphens or risky TLD on sender (+12)', 'Sender domain normal', 12))

    const subUrg = URGENCY_WORDS.filter(w => sub.includes(w))
    const r4 = subUrg.length >= 1
    if (subUrg.length >= 2) { score += 18; indicators.push({ type: 'Rule 4', detail: subUrg.join(', '), severity: 'high' }) }
    else if (r4) { score += 8; indicators.push({ type: 'Rule 4', detail: subUrg[0], severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(4, 'Urgency in Subject', r4, `${subUrg.length} urgency in subject (+${subUrg.length >= 2 ? 18 : 8})`, 'Subject calm', subUrg.length >= 2 ? 18 : 8))

    const caps = subject && subject.length > 10 ? (subject.match(/[A-Z]/g) || []).length / subject.length : 0
    const r5 = caps > 0.6
    if (r5) { score += 8; indicators.push({ type: 'Rule 5', detail: 'ALL CAPS subject', severity: 'low' }) }
    ruleEvaluations.push(ruleEval(5, 'ALL CAPS Subject', r5, `${Math.round(caps * 100)}% capitals (+8)`, 'Normal capitalization', 8))

    const bodUrg = URGENCY_WORDS.filter(w => bod.includes(w))
    const r6 = bodUrg.length >= 2
    if (bodUrg.length >= 4) { score += 22; indicators.push({ type: 'Rule 6', detail: `${bodUrg.length} urgency phrases`, severity: 'high' }) }
    else if (r6) { score += 10; indicators.push({ type: 'Rule 6', detail: bodUrg.slice(0, 2).join(', '), severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(6, 'Fear/Urgency in Body', r6, `${bodUrg.length} body urgency phrases (+${bodUrg.length >= 4 ? 22 : 10})`, 'Low body urgency', bodUrg.length >= 4 ? 22 : 10))

    const sens = SENSITIVE_WORDS.filter(w => all.includes(w))
    const r7 = sens.length >= 1
    if (sens.length >= 2) { score += 25; indicators.push({ type: 'Rule 7', detail: sens.join(', '), severity: 'high' }) }
    else if (r7) { score += 10; indicators.push({ type: 'Rule 7', detail: sens[0], severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(7, 'Sensitive Data Harvesting', r7, `${sens.length} sensitive refs (+${sens.length >= 2 ? 25 : 10})`, 'No sensitive requests', sens.length >= 2 ? 25 : 10))

    const urls = bod.match(/https?:\/\/[^\s"'<>]+/gi) || []
    const bad = urls.filter(l => { try { const h = new URL(l).hostname; return PHISHING_URL_PATTERNS.some(p => p.test(h)) || SUSPICIOUS_TLDS.some(t => h.endsWith(t)) } catch { return true } })
    const r8 = bad.length > 0
    if (r8) { score += 20; indicators.push({ type: 'Rule 8', detail: `${bad.length} bad link(s)`, severity: 'high' }) }
    ruleEvaluations.push(ruleEval(8, 'Suspicious Links', r8, `${bad.length} phishing link(s) (+20)`, 'Links OK', 20))

    const greet = ['dear customer', 'dear user', 'dear valued', 'dear sir', 'dear madam']
    const r9 = greet.some(g => bod.includes(g))
    if (r9) { score += 8; indicators.push({ type: 'Rule 9', detail: 'Generic greeting', severity: 'low' }) }
    ruleEvaluations.push(ruleEval(9, 'Generic Greeting', r9, 'Impersonal greeting (+8)', 'Personalized greeting', 8))

    const brands = BRAND_KEYWORDS.filter(b => bod.includes(b))
    const r10 = brands.length >= 1 && domain && !trusted && !brands.some(b => domain.includes(b))
    if (r10) { score += 10; indicators.push({ type: 'Rule 10', detail: `Brand ${brands[0]} mismatch`, severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(10, 'Brand Mismatch', r10, `Mentions ${brands[0]}, sender ${domain} (+10)`, 'Brand matches sender', 10))

    const threats = ['legal action', 'forfeited', 'arrest', 'permanently', 'prosecution', 'fine']
    const th = threats.filter(t => bod.includes(t))
    const r11 = th.length >= 2
    if (r11) { score += 15; indicators.push({ type: 'Rule 11', detail: th.join(', '), severity: 'high' }) }
    ruleEvaluations.push(ruleEval(11, 'Threatening Language', r11, `Threats: ${th.slice(0, 2).join(', ')} (+15)`, 'No threats', 15))

    const tgt = ['won', 'lottery', 'prize', 'congratulations', 'million', 'inheritance', 'free money']
    const tg = tgt.filter(t => all.includes(t))
    const r12 = tg.length >= 1
    if (r12) { score += 18; indicators.push({ type: 'Rule 12', detail: tg.join(', '), severity: 'high' }) }
    ruleEvaluations.push(ruleEval(12, 'Too Good To Be True', r12, `Scam offer language (+18)`, 'No scam offers', 18))

    const att = ['attached file', 'see attached', '.exe', '.zip', '.scr', 'download the attachment']
    const r13a = att.some(a => bod.includes(a))
    if (r13a) { score += 10; indicators.push({ type: 'Rule 13', detail: 'Attachment risk', severity: 'medium' }) }
    ruleEvaluations.push(ruleEval(13, 'Suspicious Attachments', r13a, 'Risky attachment refs (+10)', 'No attachment flags', 10))

    const r14 = trusted
    if (r14 && indicators.length <= 1) score = Math.max(0, score - 30)
    ruleEvaluations.push(ruleEval(14, 'Trusted Sender Whitelist', r14, `Trusted ${domain} (−30)`, 'Sender not whitelisted', -30))

    score = Math.min(100, Math.max(0, score))
    const triggered = ruleEvaluations.filter(r => r.applies && r.rule_id !== 14).length
    let verdict = score >= 60 ? 'Dangerous' : score >= 30 ? 'Suspicious' : 'Safe'

    return {
        verdict,
        risk_score: score,
        summary: verdict === 'Dangerous' ? 'High-Risk Phishing Email' : verdict === 'Suspicious' ? 'Potentially Phishing Email' : 'No Major Phishing Indicators',
        explanation: triggered ? `${triggered} of 13 threat rules triggered.` : 'All 13 threat rules clear.',
        action: verdict === 'Dangerous' ? 'Do not click links. Delete email.' : verdict === 'Suspicious' ? 'Verify sender via official channel.' : 'Normal caution advised.',
        indicators,
        iocs: indicators.map(i => ({ type: i.type, value: i.detail })),
        rule_evaluations: ruleEvaluations,
        rules_triggered: ruleEvaluations.filter(r => r.applies && r.rule_id !== 14).map(r => r.rule_id)
    }
}
