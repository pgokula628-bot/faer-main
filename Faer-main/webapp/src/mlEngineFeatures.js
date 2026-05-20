const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.icu', '.cfd', '.work', '.click', '.info']
const TRUSTED_DOMAINS = ['google.com', 'amazon.com', 'paypal.com', 'microsoft.com', 'apple.com', 'github.com', 'netflix.com', 'linkedin.com', 'zoom.us', 'wikipedia.org']
const PHISHING_LEXICON = ['urgent', 'verify', 'suspended', 'password', 'ssn', 'credit card', 'login', 'frozen', 'compromised', 'refund', 'claim', 'immediately', 'otp', 'seed phrase', 'routing', 'cvv', 'debit', 'unauthorized', 'final warning', 'legal action']
const SAFE_LEXICON = ['wikipedia', 'documentation', 'dashboard', 'enterprise', 'developer', 'invoice confirmation', 'meeting invitation', 'newsletter']

export function extractUrlFeatures(url, bodyText = '') {
    const features = {}
    let hostname = '', protocol = '', path = ''

    try {
        const u = new URL(url.startsWith('http') ? url : `https://${url}`)
        hostname = u.hostname
        protocol = u.protocol
        path = u.pathname + u.search
    } catch {
        hostname = url
    }

    const subdomainCount = Math.max(0, hostname.split('.').length - 2)
    const domainBase = hostname.replace(/\.[^.]+$/, '')
    const content = `${bodyText} ${path}`.toLowerCase()

    features.uses_http = protocol === 'http:' ? 1 : 0
    features.is_ip_host = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0
    features.suspicious_tld = SUSPICIOUS_TLDS.some(t => hostname.endsWith(t)) ? 1 : 0
    features.subdomain_heavy = subdomainCount >= 3 ? 1 : 0
    features.digit_in_host = /[0-9]/.test(domainBase) ? 1 : 0
    features.brand_typosquat = /paypa[l1]|amaz[o0]n|g[o0]{2}gle|micros[o0]ft|app[l1]e|netf[l1]ix/i.test(hostname) ? 1 : 0
    features.at_in_url = url.includes('@') ? 1 : 0
    features.url_very_long = url.length > 120 ? 1 : 0
    features.trusted_domain = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d)) ? 1 : 0
    features.urgency_density = PHISHING_LEXICON.filter(w => content.includes(w)).length / PHISHING_LEXICON.length
    features.safe_signal = SAFE_LEXICON.some(w => content.includes(w)) ? 1 : 0

    const linkHosts = (bodyText.match(/https?:\/\/[^\s"'<>]+/gi) || []).map(l => {
        try { return new URL(l).hostname } catch { return '' }
    }).filter(Boolean)
    features.suspicious_embedded_links = linkHosts.some(h =>
        !TRUSTED_DOMAINS.some(d => h === d || h.endsWith('.' + d)) &&
        (SUSPICIOUS_TLDS.some(t => h.endsWith(t)) || /paypa|amaz|secure-|verify-|login-/i.test(h))
    ) ? 1 : 0

    return { features, hostname, protocol }
}

export function extractEmailFeatures(sender, subject, body) {
    const senderLower = (sender || '').toLowerCase()
    const subjectLower = (subject || '').toLowerCase()
    const bodyLower = (body || '').toLowerCase()
    const all = `${subjectLower} ${bodyLower}`

    let domain = ''
    const m = senderLower.match(/@([a-z0-9.-]+)/)
    if (m) domain = m[1]

    const features = {}
    features.spoofed_domain = /paypa[l1]|amaz[o0]n|micros[o0]ft|g[o0]{2}gle/i.test(domain) ? 1 : 0
    features.free_email_brand_claim = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'].includes(domain) &&
        /paypal|amazon|microsoft|bank|irs|netflix/i.test(all) ? 1 : 0
    features.suspicious_sender_tld = SUSPICIOUS_TLDS.some(t => domain.endsWith(t)) ? 1 : 0
    features.subject_urgency = /urgent|immediately|frozen|final warning|act now/i.test(subjectLower) ? 1 : 0
    features.subject_all_caps = subject && subject.length > 8 && (subject.match(/[A-Z]/g) || []).length / subject.length > 0.55 ? 1 : 0
    features.body_urgency = PHISHING_LEXICON.filter(w => bodyLower.includes(w)).length >= 3 ? 1 : 0
    features.sensitive_request = /ssn|credit card|password|otp|routing|seed phrase|cvv/i.test(all) ? 1 : 0
    features.generic_greeting = /dear customer|dear user|dear valued|dear sir/i.test(bodyLower) ? 1 : 0
    features.too_good = /won|lottery|prize|million|inheritance|congratulations/i.test(all) ? 1 : 0
    features.threat_language = /legal action|forfeited|arrest|permanently deleted/i.test(bodyLower) ? 1 : 0
    features.attachment_risk = /\.exe|\.zip|attached file|download the attachment/i.test(bodyLower) ? 1 : 0
    features.trusted_sender = TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d)) ? 1 : 0

    const links = bodyLower.match(/https?:\/\/[^\s"'<>]+/gi) || []
    features.suspicious_links = links.some(l => {
        try {
            const h = new URL(l).hostname
            return SUSPICIOUS_TLDS.some(t => h.endsWith(t)) || /paypa|verify-|secure-login/i.test(h)
        } catch { return true }
    }) ? 1 : 0

    return { features, domain }
}
