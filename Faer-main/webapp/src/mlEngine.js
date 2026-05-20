/**
 * Risk scoring from URL/email features + live browser-grade threat intel (no static local datasets).
 */

import { extractUrlFeatures, extractEmailFeatures } from './mlEngineFeatures.js'
import { extractUrlsFromText } from './chromeThreatIntel.js'

export { extractUrlFeatures, extractEmailFeatures } from './mlEngineFeatures.js'

const WEBSITE_WEIGHTS = {
    uses_http: 12, is_ip_host: 20, suspicious_tld: 14, subdomain_heavy: 10,
    brand_typosquat: 22, digit_in_host: 8, urgency_density: 28, at_in_url: 15,
    suspicious_embedded_links: 16, url_very_long: 6, trusted_domain: -40, safe_signal: -15,
    live_blocklist_hit: 38
}

const EMAIL_WEIGHTS = {
    spoofed_domain: 24, free_email_brand_claim: 18, suspicious_sender_tld: 12,
    subject_urgency: 10, subject_all_caps: 6, body_urgency: 14, sensitive_request: 20,
    suspicious_links: 18, generic_greeting: 7, too_good: 16, threat_language: 12,
    attachment_risk: 8, trusted_sender: -35, live_blocklist_hit: 35
}

function scoreFeatures(features, weights, liveIntel) {
    let score = 0
    const risk_factors = []

    if (liveIntel?.any_threat) {
        features.live_blocklist_hit = 1
        risk_factors.push(liveIntel.summary)
    }

    Object.entries(weights).forEach(([key, w]) => {
        const v = features[key] || 0
        if (v > 0 && w > 0) {
            score += w * (typeof v === 'number' && v < 1 ? v : 1)
            if (w >= 10) {
                risk_factors.push(`${humanize(key)} increases suspicion.`)
            }
        } else if (v > 0 && w < 0) {
            score += w
            risk_factors.push(`${humanize(key)} reduces overall risk.`)
        }
    })

    return { score: Math.max(0, score), risk_factors: [...new Set(risk_factors)] }
}

function humanize(key) {
    const m = {
        uses_http: 'Unencrypted HTTP connection',
        is_ip_host: 'Numeric IP address instead of a branded domain',
        suspicious_tld: 'High-risk domain extension',
        brand_typosquat: 'Domain resembles a famous brand with alterations',
        urgency_density: 'Heavy urgency or pressure wording',
        sensitive_request: 'Requests for passwords or financial data',
        spoofed_domain: 'Sender domain imitates a trusted organization',
        live_blocklist_hit: 'Address appears on a live phishing blocklist'
    }
    return m[key] || key.replace(/_/g, ' ')
}

function scoreToVerdict(score) {
    if (score >= 55) return 'Dangerous'
    if (score >= 28) return 'Suspicious'
    return 'Safe'
}

export function analyzeWebsiteWithML(url, bodyText, liveIntel = null) {
    const { features } = extractUrlFeatures(url, bodyText)
    const { score, risk_factors } = scoreFeatures(features, WEBSITE_WEIGHTS, liveIntel)
    const risk_score = Math.min(100, Math.round(score * 0.85 + (liveIntel?.risk_boost || 0)))

    return {
        verdict: scoreToVerdict(score + (liveIntel?.risk_boost || 0) / 2),
        risk_score,
        confidence: Math.min(98, 50 + risk_score / 2),
        risk_factors,
        why_suspicious: risk_factors.length
            ? risk_factors.join(' ')
            : 'Structural signals align with normal legitimate websites.',
        feature_snapshot: features
    }
}

export function analyzeEmailWithML(sender, subject, body, liveIntel = null) {
    const { features } = extractEmailFeatures(sender, subject, body)
    const linkUrls = extractUrlsFromText(body)
    if (liveIntel?.any_threat) features.live_blocklist_hit = 1

    const { score, risk_factors } = scoreFeatures(features, EMAIL_WEIGHTS, liveIntel)
    const risk_score = Math.min(100, Math.round(score * 0.85 + (liveIntel?.risk_boost || 0)))

    return {
        verdict: scoreToVerdict(score + (liveIntel?.risk_boost || 0) / 2),
        risk_score,
        confidence: Math.min(98, 50 + risk_score / 2),
        risk_factors,
        why_suspicious: risk_factors.length
            ? risk_factors.join(' ')
            : 'Message patterns resemble routine legitimate correspondence.',
        feature_snapshot: features
    }
}
