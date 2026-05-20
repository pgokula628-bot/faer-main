/**
 * Real-time threat intelligence (same class of feeds Chrome uses for phishing warnings).
 * - Google Safe Browsing API v4 (browser blocklist source)
 * - OpenPhish live feed (active phishing URLs, refreshed continuously)
 */

const OPENPHISH_CACHE_MS = 5 * 60 * 1000
let openPhishCache = { urls: new Set(), fetchedAt: 0 }

function getApiKey() {
    return import.meta.env.VITE_SAFE_BROWSING_API_KEY ||
        import.meta.env.VITE_GOOGLE_API_KEY ||
        import.meta.env.VITE_GEMINI_API_KEY ||
        ''
}

function normalizeUrl(url) {
    try {
        const u = new URL(url.startsWith('http') ? url : `https://${url}`)
        return u.href
    } catch {
        return url
    }
}

function hostMatchesList(hostname, urlSet) {
    const h = hostname.toLowerCase()
    for (const entry of urlSet) {
        try {
            const eu = new URL(entry.startsWith('http') ? entry : `https://${entry}`)
            const eh = eu.hostname.toLowerCase()
            if (h === eh || h.endsWith('.' + eh) || entry.includes(h)) return { matched: true, entry }
        } catch {
            if (entry.includes(h)) return { matched: true, entry }
        }
    }
    return { matched: false, entry: null }
}

/** Google Safe Browsing — real-time list used by Chrome for phishing/malware interstitials */
export async function checkGoogleSafeBrowsing(url) {
    const key = getApiKey()
    if (!key) {
        return { checked: false, threat: false, threatTypes: [], detail: 'Live browser threat database check skipped (no API key configured).' }
    }

    const target = normalizeUrl(url)
    const body = {
        client: { clientId: 'threatlens', clientVersion: '1.0.0' },
        threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: target }]
        }
    }

    try {
        const apiBase = import.meta.env.DEV
            ? '/api/safebrowsing/v4/threatMatches:find'
            : `https://safebrowsing.googleapis.com/v4/threatMatches:find`
        const endpoint = import.meta.env.DEV ? apiBase : `${apiBase}?key=${key}`

        const resp = await fetch(import.meta.env.DEV ? `${apiBase}?key=${key}` : endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })

        if (!resp.ok) {
            return { checked: true, threat: false, threatTypes: [], detail: `Safe Browsing lookup unavailable (${resp.status}).` }
        }

        const data = await resp.json()
        const matches = data.matches || []
        const types = [...new Set(matches.map(m => m.threatType).filter(Boolean))]

        if (matches.length > 0) {
            return {
                checked: true,
                threat: true,
                threatTypes: types,
                detail: `This URL is flagged on the live browser phishing/malware blocklist (same class of data Chrome uses): ${types.join(', ').replace(/_/g, ' ').toLowerCase()}.`
            }
        }
        return {
            checked: true,
            threat: false,
            threatTypes: [],
            detail: 'Not listed on the current Safe Browsing phishing/malware blocklist.'
        }
    } catch (e) {
        return { checked: false, threat: false, threatTypes: [], detail: `Safe Browsing check failed: ${e.message}` }
    }
}

/** OpenPhish — continuously updated active phishing URL feed */
export async function fetchOpenPhishFeed() {
    const now = Date.now()
    if (openPhishCache.urls.size > 0 && now - openPhishCache.fetchedAt < OPENPHISH_CACHE_MS) {
        return openPhishCache.urls
    }

    try {
        const feedUrl = import.meta.env.DEV ? '/api/openphish/feed.txt' : 'https://openphish.com/feed.txt'
        const resp = await fetch(feedUrl, { cache: 'no-store' })
        if (!resp.ok) throw new Error(`Feed ${resp.status}`)
        const text = await resp.text()
        const urls = new Set(
            text.split('\n')
                .map(l => l.trim())
                .filter(l => l.startsWith('http'))
        )
        openPhishCache = { urls, fetchedAt: now }
        return urls
    } catch {
        return openPhishCache.urls.size ? openPhishCache.urls : new Set()
    }
}

export async function checkOpenPhish(url) {
    const feed = await fetchOpenPhishFeed()
    if (!feed.size) {
        return { checked: false, threat: false, detail: 'Active phishing feed temporarily unavailable.' }
    }

    let hostname = ''
    try { hostname = new URL(normalizeUrl(url)).hostname } catch { hostname = url }

    const { matched, entry } = hostMatchesList(hostname, feed)
    if (matched) {
        return {
            checked: true,
            threat: true,
            detail: `Hostname matches an entry on the live OpenPhish active-phishing feed (${entry || hostname}).`,
            matchedEntry: entry
        }
    }
    return {
        checked: true,
        threat: false,
        detail: 'No match on the current live active-phishing URL feed.'
    }
}

/** Check primary URL + links found in page/email body */
export async function fetchLiveThreatIntel(primaryUrl, extraUrls = []) {
    const unique = [...new Set([primaryUrl, ...extraUrls].filter(Boolean).map(normalizeUrl))]
    const results = []

    for (const u of unique.slice(0, 5)) {
        const [sb, op] = await Promise.all([
            checkGoogleSafeBrowsing(u),
            checkOpenPhish(u)
        ])
        results.push({ url: u, safeBrowsing: sb, openPhish: op })
    }

    const anyThreat = results.some(r => r.safeBrowsing.threat || r.openPhish.threat)
    const threatLines = []
    results.forEach(r => {
        if (r.safeBrowsing.threat) threatLines.push(r.safeBrowsing.detail)
        if (r.openPhish.threat) threatLines.push(r.openPhish.detail)
    })

    return {
        checked_at: new Date().toISOString(),
        any_threat: anyThreat,
        risk_boost: anyThreat ? 35 : 0,
        results,
        summary: anyThreat
            ? threatLines.join(' ')
            : (results[0]?.safeBrowsing?.checked
                ? 'Checked against live browser-grade blocklists; no active listing found for this address.'
                : 'Live blocklist check partially unavailable; analysis relies on structural and content signals.')
    }
}

export function extractUrlsFromText(text) {
    return (text || '').match(/https?:\/\/[^\s"'<>]+/gi) || []
}
