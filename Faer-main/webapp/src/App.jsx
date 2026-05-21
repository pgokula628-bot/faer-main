import { useState, useEffect } from 'react'
import { Shield, Clock, LayoutDashboard, Terminal, AlertTriangle, Zap, Globe, ChevronRight, Activity, LogOut, User, Menu, X, Mail, Send, Inbox, AlertCircle, CheckCircle } from 'lucide-react'
import Login from './Login'
import Register from './Register'
import { analyzeWebsite, analyzeEmail } from './ruleEngine'
import { buildUnifiedThreatAnalysis, mergeFullReport } from './threatAnalysis'
import { fetchLiveThreatIntel, extractUrlsFromText } from './chromeThreatIntel'
import ThreatAnalysisReport from './ThreatAnalysisReport'

const getHistory = () => JSON.parse(localStorage.getItem('scan_history') || '[]')
const saveHistory = (newItem) => {
    const current = getHistory()
    const updated = [newItem, ...current].slice(0, 50)
    localStorage.setItem('scan_history', JSON.stringify(updated))
    return updated
}

const getCacheKey = (type, param1, param2 = '') => {
    const raw = `${type}||${param1}||${param2}`;
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
        hash = (hash << 5) - hash + raw.charCodeAt(i);
        hash |= 0;
    }
    return `threat_cache_${type}_${hash}`;
}

const getCachedReport = (type, param1, param2 = '') => {
    try {
        const cached = localStorage.getItem(getCacheKey(type, param1, param2))
        return cached ? JSON.parse(cached) : null
    } catch { return null }
}

const setCachedReport = (type, param1, param2 = '', report) => {
    try {
        localStorage.setItem(getCacheKey(type, param1, param2), JSON.stringify(report))
    } catch (e) { console.error('Cache set failed', e) }
}

function App() {
    const [user, setUser] = useState(null)
    const [authView, setAuthView] = useState('login') // 'login' or 'register'
    const [url, setUrl] = useState(null)
    const [status, setStatus] = useState('idle')
    const [report, setReport] = useState(null)
    const [history, setHistory] = useState(getHistory())
    const [view, setView] = useState('dashboard')
    const [loadingMsg, setLoadingMsg] = useState("Initializing Scanner...")
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

    // Email Scanner State
    const [emailSender, setEmailSender] = useState('')
    const [emailSubject, setEmailSubject] = useState('')
    const [emailBody, setEmailBody] = useState('')
    const [emailStatus, setEmailStatus] = useState('idle')
    const [emailReport, setEmailReport] = useState(null)
    const [emailLoadingMsg, setEmailLoadingMsg] = useState('Initializing Email Scanner...')

    // Check for existing session and ensure demo user exists
    useEffect(() => {
        const users = JSON.parse(localStorage.getItem('threatlens_users') || '[]')
        const demoExists = users.find(u => u.email === 'demo@threatlens.ai')

        if (!demoExists) {
            const demoUser = {
                id: 'demo',
                name: 'Gokul',
                email: 'demo@threatlens.ai',
                password: 'demo123',
                createdAt: new Date().toISOString()
            }
            users.push(demoUser)
            localStorage.setItem('threatlens_users', JSON.stringify(users))
        }

        const currentUser = localStorage.getItem('threatlens_current_user')
        if (currentUser) {
            setUser(JSON.parse(currentUser))
        }
    }, [])

    // Analysis phase tracking
    const [analysisPhase, setAnalysisPhase] = useState('idle') // idle, gemini, rules, ml, done
    const [emailAnalysisPhase, setEmailAnalysisPhase] = useState('idle')

    useEffect(() => {
        if (status === 'analyzing') {
            const msgs = {
                live: ["Checking live browser blocklists...", "Querying active phishing feeds...", "Verifying real-time reputation..."],
                gemini: ["Running deep security analysis...", "Evaluating safe vs unsafe signals...", "Building detailed evidence..."],
                rules: ["Applying 13 website security rules...", "Checking HTTPS, TLD, typosquatting...", "Scanning content patterns..."],
                ml: ["Scoring structural risk profile...", "Correlating live threat data...", "Finalizing assessment..."]
            }[analysisPhase] || ["Initializing threat scan..."]
            let i = 0
            const interval = setInterval(() => {
                setLoadingMsg(msgs[i % msgs.length])
                i++
            }, 600)
            return () => clearInterval(interval)
        }
    }, [status, analysisPhase])

    useEffect(() => {
        if (emailStatus === 'analyzing') {
            const msgs = {
                live: ["Checking links against live blocklists...", "Verifying sender reputation...", "Loading active threat feeds..."],
                gemini: ["Running deep email analysis...", "Evaluating phishing indicators...", "Building detailed evidence..."],
                rules: ["Applying 14 email security rules...", "Checking spoofed sender and links...", "Scanning urgency and attachments..."],
                ml: ["Scoring message risk profile...", "Correlating live threat data...", "Finalizing assessment..."]
            }[emailAnalysisPhase] || ["Initializing email scan..."]
            let i = 0
            const interval = setInterval(() => {
                setEmailLoadingMsg(msgs[i % msgs.length])
                i++
            }, 600)
            return () => clearInterval(interval)
        }
    }, [emailStatus, emailAnalysisPhase])

    useEffect(() => {
        const params = new URLSearchParams(window.location.search)
        const typeParam = params.get('type')

        if (typeParam === 'website') {
            const urlParam = params.get('url')
            const textParam = params.get('text')
            if (urlParam) {
                setView('dashboard')
                setUrl(urlParam)
                setStatus('analyzing')
                runAnalysis(urlParam, textParam)
            }
            window.history.replaceState({}, document.title, "/")
        } else if (typeParam === 'email') {
            const senderParam = params.get('sender') || ''
            const subjectParam = params.get('subject') || ''
            const bodyParam = params.get('body') || ''

            setView('email')
            setEmailSender(senderParam)
            setEmailSubject(subjectParam)
            setEmailBody(bodyParam)

            if (senderParam || subjectParam || bodyParam) {
                setTimeout(() => {
                    runEmailAnalysis(senderParam, subjectParam, bodyParam)
                }, 100)
            }
            window.history.replaceState({}, document.title, "/")
        } else {
            const urlParam = params.get('url')
            const textParam = params.get('text')
            if (urlParam) {
                setView('dashboard')
                setUrl(urlParam)
                setStatus('analyzing')
                runAnalysis(urlParam, textParam)
                window.history.replaceState({}, document.title, "/")
            }
        }
    }, [])


    const callGeminiLLM = async (prompt, retryCount = 0) => {
        const key = import.meta.env.VITE_GEMINI_API_KEY
        if (!key) return null

        const modelsResp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${key}`)
        if (modelsResp.status === 429) throw new Error("RATE_LIMIT")
        if (!modelsResp.ok) throw new Error("API Connection Failed")

        const modelsData = await modelsResp.json()
        const validModel = modelsData.models?.find(m =>
            m.supportedGenerationMethods?.includes("generateContent") &&
            (m.name.includes("flash") || m.name.includes("pro"))
        )
        if (!validModel) throw new Error("No AI Model Available")
        const modelName = validModel.name.replace("models/", "")

        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${key}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: {
                    temperature: 0.2,
                    responseMimeType: 'application/json'
                }
            })
        })

        if (response.status === 429) {
            if (retryCount < 2) {
                const delay = Math.pow(2, retryCount) * 1000
                await new Promise(resolve => setTimeout(resolve, delay))
                return callGeminiLLM(prompt, retryCount + 1)
            }
            throw new Error("RATE_LIMIT")
        }
        if (!response.ok) throw new Error("Analysis Failed")

        const data = await response.json()
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "{}"
        try {
            return JSON.parse(text.replace(/```json/g, '').replace(/```/g, '').trim())
        } catch {
            const match = text.match(/\{[\s\S]*\}/)
            if (match) return JSON.parse(match[0])
            throw new Error("Invalid AI response")
        }
    }

    const buildWebsiteGeminiPrompt = (targetUrl, targetText, ruleResult, liveIntel) => {
        const rulesSummary = JSON.stringify(ruleResult.rule_evaluations || [])
        return `You are a senior cybersecurity analyst writing a report for a non-technical user.

CRITICAL: Do NOT mention AI, machine learning, APIs, models, Gemini, datasets, or any software tools. Write only factual security analysis.

URL: ${targetUrl}
Page content: ${(targetText || '').substring(0, 4000)}
Live blocklist check: ${liveIntel?.summary || 'unavailable'}
Rule scan data: ${rulesSummary}

For ALL 13 rules, state whether each rule FITS (yes) or DOES NOT FIT (no) with specific evidence from the URL/content.
Explain in detail why this site is SAFE or UNSAFE. Reference live blocklist results naturally (e.g. "listed on active phishing blocklists") without naming vendors.

Return ONLY valid JSON:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "risk_score": 0-100,
  "summary": "one line headline",
  "detailed_analysis": "3-6 sentences, rich detail, no tool names",
  "why_safe": ["detailed reason 1", "reason 2"],
  "why_unsafe": ["detailed reason 1", "reason 2"],
  "rule_assessments": [{"rule_id": 1, "rule_name": "HTTP vs HTTPS", "fits": true, "evidence": "specific fact"}],
  "evidence": [{"category": "Connection", "finding": "fact", "implication": "what it means"}],
  "action": "clear user advice"
}`
    }

    const buildEmailGeminiPrompt = (sender, subject, body, ruleResult, liveIntel) => {
        const rulesSummary = JSON.stringify(ruleResult.rule_evaluations || [])
        return `You are a senior cybersecurity analyst writing a report for a non-technical user.

CRITICAL: Do NOT mention AI, machine learning, APIs, models, or any software tools. Write only factual security analysis.

Sender: ${sender}
Subject: ${subject}
Body: ${body.substring(0, 5000)}
Live blocklist check on links: ${liveIntel?.summary || 'unavailable'}
Rule scan data: ${rulesSummary}

For ALL 14 rules, state FITS yes/no with evidence. Rule 1 (spoofed sender) must be answered explicitly.
Explain in detail why this email is SAFE or UNSAFE.

Return ONLY valid JSON:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "risk_score": 0-100,
  "summary": "headline",
  "detailed_analysis": "3-6 sentences, rich detail",
  "why_safe": ["reason"],
  "why_unsafe": ["reason"],
  "rule_assessments": [{"rule_id": 1, "rule_name": "Spoofed Sender", "fits": false, "evidence": "..."}],
  "evidence": [{"category": "Sender", "finding": "...", "implication": "..."}],
  "action": "advice"
}`
    }

    const finalizeWebsiteReport = (targetUrl, targetText, gemini, rules, ml, liveIntel) => {
        const unified = buildUnifiedThreatAnalysis({
            gemini, rules, ml, liveIntel, targetLabel: 'website', maxRules: 13
        })
        return mergeFullReport({
            ...rules,
            url: targetUrl,
            summary: gemini?.summary || rules.summary,
            action: gemini?.action || rules.action,
            timestamp: new Date().toISOString()
        }, unified)
    }

    const finalizeEmailReport = (gemini, rules, ml, liveIntel) => {
        const unified = buildUnifiedThreatAnalysis({
            gemini, rules, ml, liveIntel, targetLabel: 'email', maxRules: 14
        })
        return mergeFullReport({
            ...rules,
            summary: gemini?.summary || rules.summary,
            action: gemini?.action || rules.action
        }, unified)
    }

    const runAnalysis = async (targetUrl, targetText) => {
        setStatus('analyzing')
        setAnalysisPhase('live')

        const cached = getCachedReport('website', targetUrl, targetText || '')
        if (cached?.analysis_mode === 'unified-v2') {
            setReport(cached)
            setHistory(saveHistory(cached))
            setAnalysisPhase('done')
            setStatus('success')
            return
        }

        try {
            const extraUrls = extractUrlsFromText(targetText || '')
            const liveIntel = await fetchLiveThreatIntel(targetUrl, extraUrls)

            setAnalysisPhase('gemini')
            let gemini = null
            try {
                const rulesPreview = analyzeWebsite(targetUrl, targetText || '')
                gemini = await callGeminiLLM(buildWebsiteGeminiPrompt(targetUrl, targetText, rulesPreview, liveIntel))
            } catch (e) {
                console.warn('Analysis API skipped:', e.message)
            }

            setAnalysisPhase('rules')
            await new Promise(r => setTimeout(r, 300))
            const rules = analyzeWebsite(targetUrl, targetText || '')

            setAnalysisPhase('ml')
            await new Promise(r => setTimeout(r, 300))
            let ml = { verdict: 'Safe', risk_score: 0, risk_factors: [], why_suspicious: '', feature_snapshot: {} }
            try {
                const mlResponse = await fetch('http://localhost:5000/api/analyze/url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: targetUrl, bodyText: targetText || '', liveIntel })
                })
                if (mlResponse.ok) {
                    ml = await mlResponse.json()
                }
            } catch (e) {
                console.error('Python ML Backend disconnected or errored:', e)
            }

            const finalReport = finalizeWebsiteReport(targetUrl, targetText, gemini, rules, ml, liveIntel)
            setCachedReport('website', targetUrl, targetText || '', finalReport)
            setReport(finalReport)
            setHistory(saveHistory(finalReport))
            setAnalysisPhase('done')
            setStatus('success')
        } catch (err) {
            console.error(err)
            setReport({
                verdict: 'Error',
                risk_score: 0,
                summary: 'Analysis Error',
                threat_analysis: err.message,
                action: 'Please try again.',
                indicators: []
            })
            setStatus('error')
            setAnalysisPhase('idle')
        }
    }

    const runEmailAnalysis = async (directSender, directSubject, directBody) => {
        const useSender = directSender !== undefined ? directSender : emailSender
        const useSubject = directSubject !== undefined ? directSubject : emailSubject
        const useBody = directBody !== undefined ? directBody : emailBody

        setEmailStatus('analyzing')
        setEmailAnalysisPhase('live')

        const cached = getCachedReport('email', useSender, useSubject + '||' + useBody)
        if (cached?.analysis_mode === 'unified-v2') {
            setEmailReport(cached)
            setEmailAnalysisPhase('done')
            setEmailStatus('success')
            return
        }

        try {
            const linkUrls = extractUrlsFromText(useBody)
            const liveIntel = await fetchLiveThreatIntel(linkUrls[0] || `mailto:${useSender}`, linkUrls)

            setEmailAnalysisPhase('gemini')
            let gemini = null
            try {
                const rulesPreview = analyzeEmail(useSender, useSubject, useBody)
                gemini = await callGeminiLLM(buildEmailGeminiPrompt(useSender, useSubject, useBody, rulesPreview, liveIntel))
            } catch (e) {
                console.warn('Analysis API skipped:', e.message)
            }

            setEmailAnalysisPhase('rules')
            await new Promise(r => setTimeout(r, 300))
            const rules = analyzeEmail(useSender, useSubject, useBody)

            setEmailAnalysisPhase('ml')
            await new Promise(r => setTimeout(r, 300))
            let ml = { verdict: 'Safe', risk_score: 0, risk_factors: [], why_suspicious: '', feature_snapshot: {} }
            try {
                const mlResponse = await fetch('http://localhost:5000/api/analyze/email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sender: useSender, subject: useSubject, body: useBody, liveIntel })
                })
                if (mlResponse.ok) {
                    ml = await mlResponse.json()
                }
            } catch (e) {
                console.error('Python ML Backend disconnected or errored:', e)
            }

            const finalReport = finalizeEmailReport(gemini, rules, ml, liveIntel)
            setCachedReport('email', useSender, useSubject + '||' + useBody, finalReport)
            setEmailReport(finalReport)
            setEmailAnalysisPhase('done')
            setEmailStatus('success')
        } catch (err) {
            console.error(err)
            setEmailReport({
                verdict: 'Error',
                risk_score: 0,
                summary: 'Analysis Error',
                threat_analysis: err.message,
                action: 'Please try again.',
                indicators: []
            })
            setEmailStatus('error')
            setEmailAnalysisPhase('idle')
        }
    }

    const handleEmailScan = (e) => {
        e.preventDefault()
        if (!emailSender.trim() && !emailSubject.trim() && !emailBody.trim()) return
        runEmailAnalysis()
    }

    const handleLogin = (userData) => {
        setUser(userData)
    }

    const handleRegister = (userData) => {
        setUser(userData)
    }

    const handleLogout = () => {
        localStorage.removeItem('threatlens_current_user')
        setUser(null)
        setView('dashboard')
    }

    // If not logged in, show auth screens
    if (!user) {
        if (authView === 'login') {
            return <Login onLogin={handleLogin} onSwitchToRegister={() => setAuthView('register')} />
        } else {
            return <Register onRegister={handleRegister} onSwitchToLogin={() => setAuthView('login')} />
        }
    }

    const stats = {
        total: history.length,
        safe: history.filter(h => h.verdict === 'Safe').length,
        threats: history.filter(h => h.verdict !== 'Safe').length
    }

    return (
        <div className="app-shell">
            {/* MOBILE HEADER */}
            <div className="mobile-header">
                <div className="mobile-brand">
                    <Shield size={24} />
                    <span>Threat Lens</span>
                </div>
                <button
                    className="hamburger-btn"
                    onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                    aria-label="Toggle menu"
                >
                    {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
                </button>
            </div>

            {/* SIDEBAR */}
            <aside className={`sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
                <div className="brand-section">
                    <div className="brand-logo">
                        <Shield size={22} />
                    </div>
                    <div className="brand-text">
                        <h2>Threat Lens</h2>
                        <span>Threat Detection Platform</span>
                    </div>
                </div>

                <nav className="nav-list">
                    <button
                        className={`nav-link ${view === 'dashboard' ? 'active' : ''}`}
                        onClick={() => { setView('dashboard'); setMobileMenuOpen(false); }}
                    >
                        <LayoutDashboard size={18} />
                        <span>Overview</span>
                    </button>
                    <button
                        className={`nav-link ${view === 'history' ? 'active' : ''}`}
                        onClick={() => { setView('history'); setMobileMenuOpen(false); }}
                    >
                        <Clock size={18} />
                        <span>Scan History</span>
                    </button>
                    <button
                        className={`nav-link ${view === 'email' ? 'active' : ''}`}
                        onClick={() => { setView('email'); setMobileMenuOpen(false); }}
                    >
                        <Mail size={18} />
                        <span>Email Scanner</span>
                    </button>
                </nav>



                <div className="user-profile">
                    <div className="profile-info">
                        <div className="profile-avatar">
                            {user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)}
                        </div>
                        <div className="profile-details">
                            <div className="profile-name">{user.name}</div>
                            <div className="profile-email">{user.email}</div>
                        </div>
                    </div>
                    <button onClick={handleLogout} className="logout-btn" title="Logout">
                        <LogOut size={18} />
                    </button>
                </div>
            </aside>

            {/* MAIN CONTENT */}
            <main className="content-area">

                {view === 'dashboard' && (
                    <>
                        {/* HEADER WITH STATS */}
                        <div className="page-header">
                            <div className="header-main">
                                <h1>Security Dashboard</h1>
                                <p>Real-time threat analysis and detection</p>
                            </div>
                            <div className="header-stats">
                                <div className="stat-card">
                                    <div className="stat-icon"><Activity size={16} /></div>
                                    <div className="stat-content">
                                        <div className="stat-value">{stats.total}</div>
                                        <div className="stat-label">Total Scans</div>
                                    </div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-icon safe"><Shield size={16} /></div>
                                    <div className="stat-content">
                                        <div className="stat-value">{stats.safe}</div>
                                        <div className="stat-label">Safe</div>
                                    </div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-icon danger"><AlertTriangle size={16} /></div>
                                    <div className="stat-content">
                                        <div className="stat-value">{stats.threats}</div>
                                        <div className="stat-label">Threats</div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="dashboard-content">

                            {/* MAIN ANALYSIS SECTION */}
                            <div className="main-section">
                                <div className="analysis-card cyber-corners">
                                    {status === 'idle' && (
                                        <div className="state-empty">
                                            <div className="icon-ring"><Zap size={32} /></div>
                                            <h3>Ready to Scan</h3>
                                            <p>Trigger a security scan from your browser extension</p>
                                        </div>
                                    )}

                                    {status === 'analyzing' && (
                                        <div className="state-analyzing">
                                            <div className="simple-scanning-loader">
                                                <div className="simple-spinner">
                                                    <Shield size={38} className="simple-spinner-shield" />
                                                </div>
                                            </div>
                                            <h3>{loadingMsg}</h3>
                                            <div className="target-url">{url}</div>
                                            <div className="simple-progress-track">
                                                <div className="simple-progress-bar"></div>
                                            </div>
                                        </div>
                                    )}

                                    {status === 'success' && report && (
                                        <div className="report-container">
                                            <div className="report-header">
                                                <div className="verdict-section">
                                                    <div className={`verdict-chip ${report.verdict.toLowerCase()}`}>
                                                        {report.verdict}
                                                    </div>
                                                    <p className="report-title">{report.summary}</p>
                                                </div>
                                                <div className="risk-section">
                                                    <div className="risk-label">Risk Score</div>
                                                    <div className="risk-value">
                                                        <span className="risk-val">{report.risk_score}</span>
                                                        <span className="risk-max">/100</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <ThreatAnalysisReport report={report} />
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* SIDEBAR: RECENT ACTIVITY */}
                            <div className="side-section">
                                {/* CYBER TELEMETRY DASHBOARD */}
                                <div className="cyber-telemetry-container">
                                    {/* GRAPH CARD */}
                                    <div className="telemetry-card cyber-corners">
                                        <div className="telemetry-card-title">
                                            <Activity size={14} />
                                            <span>Threat Level Log Analysis</span>
                                        </div>
                                        <div className="telemetry-svg-wrap">
                                            <svg viewBox="0 0 350 150" width="100%" height="100%">
                                                <defs>
                                                    <filter id="cyber-glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                                                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                                                        <feMerge>
                                                            <feMergeNode in="blur"/>
                                                            <feMergeNode in="SourceGraphic"/>
                                                        </feMerge>
                                                    </filter>
                                                    <linearGradient id="cyber-area-cyan" x1="0" y1="0" x2="0" y2="1">
                                                        <stop offset="0%" stopColor="var(--accent-primary)" stopOpacity="0.2" />
                                                        <stop offset="100%" stopColor="var(--accent-primary)" stopOpacity="0.0" />
                                                    </linearGradient>
                                                </defs>
                                                
                                                {/* Grid lines */}
                                                <line x1="20" y1="20" x2="330" y2="20" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                                <line x1="20" y1="60" x2="330" y2="60" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                                <line x1="20" y1="100" x2="330" y2="100" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                                <line x1="20" y1="140" x2="330" y2="140" stroke="rgba(0, 210, 255, 0.12)" strokeWidth="1.5" />
                                                
                                                {/* Trend line and fill */}
                                                <path d={(() => {
                                                    const dPoints = history.length > 0
                                                        ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 }))
                                                        : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                                    const pathString = dPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
                                                    return pathString;
                                                })()} fill="none" stroke="var(--accent-primary)" strokeWidth="2.5" filter="url(#cyber-glow-cyan)" />
                                                
                                                <path d={(() => {
                                                    const dPoints = history.length > 0
                                                        ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 }))
                                                        : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                                    const pathString = dPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
                                                    return `${pathString} L ${dPoints[dPoints.length - 1].x} 140 L ${dPoints[0].x} 140 Z`;
                                                })()} fill="url(#cyber-area-cyan)" />
                                                
                                                {/* Data points */}
                                                {(() => {
                                                    const dPoints = history.length > 0
                                                        ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 }))
                                                        : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                                    return dPoints.map((p, i) => (
                                                        <circle key={i} cx={p.x} cy={p.y} r="3.5" fill="var(--bg-primary)" stroke="var(--accent-primary)" strokeWidth="2" />
                                                    ));
                                                })()}
                                            </svg>
                                        </div>
                                    </div>

                                    {/* GAUGE CARD */}
                                    <div className="telemetry-card cyber-corners">
                                        <div className="telemetry-card-title">
                                            <Shield size={14} />
                                            <span>Security Integrity Index</span>
                                        </div>
                                        <div className="telemetry-svg-wrap">
                                            <svg viewBox="0 0 200 150" width="100%" height="100%">
                                                <defs>
                                                    <filter id="cyber-glow-violet" x="-20%" y="-20%" width="140%" height="140%">
                                                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                                                        <feMerge>
                                                            <feMergeNode in="blur"/>
                                                            <feMergeNode in="SourceGraphic"/>
                                                        </feMerge>
                                                    </filter>
                                                </defs>
                                                
                                                {/* Track circle */}
                                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="8" />
                                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(0, 210, 255, 0.05)" strokeWidth="8" strokeDasharray="301.6" strokeDashoffset="0" />
                                                
                                                {/* Progress Arc */}
                                                <circle cx="100" cy="70" r="48" fill="none" stroke="var(--accent-violet)" strokeWidth="6" 
                                                    strokeDasharray="301.6" 
                                                    strokeDashoffset={(() => {
                                                        const ratio = stats.total > 0 ? stats.safe / stats.total : 0.85;
                                                        return 301.6 - (301.6 * ratio);
                                                    })()}
                                                    strokeLinecap="round"
                                                    filter="url(#cyber-glow-violet)"
                                                    transform="rotate(-90 100 70)"
                                                />
                                                
                                                {/* Inner Telemetry Text */}
                                                <text x="100" y="68" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontWeight="700" fontFamily="Space Grotesk">
                                                    {(() => {
                                                        const ratio = stats.total > 0 ? Math.round((stats.safe / stats.total) * 100) : 85;
                                                        return `${ratio}%`;
                                                    })()}
                                                </text>
                                                <text x="100" y="85" textAnchor="middle" fill="var(--text-tertiary)" fontSize="8" fontWeight="600" textTransform="uppercase" letterSpacing="0.8" fontFamily="Inter">
                                                    Safe Ratio
                                                </text>
                                                
                                                {/* Glowing indicator light */}
                                                <circle cx="100" cy="70" r="54" className="radial-pulse-glow" fill="none" stroke="var(--accent-primary)" strokeWidth="0.5" strokeDasharray="4 8" />
                                            </svg>
                                        </div>
                                    </div>
                                </div>

                                <div className="section-header">
                                    <h2>Recent Activity</h2>
                                    <p>Latest {history.length > 5 ? 5 : history.length} scans</p>
                                </div>

                                <div className="activity-list">
                                    {history.slice(0, 5).map((h, i) => (
                                        <div key={i} className="activity-item">
                                            <div className="activity-icon">
                                                <Globe size={14} />
                                            </div>
                                            <div className="activity-details">
                                                <div className="activity-domain">{new URL(h.url).hostname}</div>
                                                <div className="activity-time">{new Date(h.timestamp).toLocaleTimeString()}</div>
                                            </div>
                                            <div className={`activity-badge ${h.verdict.toLowerCase()}`}>
                                                {h.verdict}
                                            </div>
                                        </div>
                                    ))}
                                    {history.length === 0 && (
                                        <div className="empty-activity">
                                            <p>No recent scans</p>
                                        </div>
                                    )}
                                </div>
                            </div>

                        </div>
                    </>
                )}

                {view === 'history' && (
                    <div className="history-page">
                        <div className="page-header">
                            <div className="header-main">
                                <h1>Scan History</h1>
                                <p>Complete record of all security scans</p>
                            </div>
                        </div>

                        <div className="history-content">
                            <div className="history-grid">
                                {history.map((h, i) => (
                                    <div
                                        key={i}
                                        className="history-card"
                                        onClick={() => { setReport(h); setStatus('success'); setView('dashboard'); }}
                                    >
                                        <div className="card-header">
                                            <div className={`status-dot ${h.verdict.toLowerCase()}`}></div>
                                            <span className="card-domain">{new URL(h.url).hostname}</span>
                                        </div>
                                        <div className="card-summary">{h.summary}</div>
                                        <div className="card-footer">
                                            <span className="card-time">{new Date(h.timestamp).toLocaleString()}</span>
                                            <span className="card-score">Risk: {h.risk_score}/100</span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}

                {view === 'email' && (
                    <div className="email-scanner-page">
                        <div className="page-header">
                            <div className="header-main">
                                <h1>Email Threat Scanner</h1>
                                <p>Detect phishing and malicious emails before you click</p>
                            </div>
                        </div>

                        <div className="email-scanner-content">
                            {/* EMAIL INPUT FORM */}
                            <div className="email-form-section">
                                <div className="section-header">
                                    <h2>Analyze Email</h2>
                                    <p>Paste the email details below for AI-powered threat analysis</p>
                                </div>

                                <form onSubmit={handleEmailScan} className="email-form-card">
                                    <div className="email-field">
                                        <label htmlFor="emailSender">
                                            <Mail size={14} />
                                            <span>Sender Address</span>
                                        </label>
                                        <input
                                            id="emailSender"
                                            type="text"
                                            value={emailSender}
                                            onChange={(e) => setEmailSender(e.target.value)}
                                            placeholder='e.g. support@paypa1-security.com'
                                        />
                                    </div>

                                    <div className="email-field">
                                        <label htmlFor="emailSubject">
                                            <Inbox size={14} />
                                            <span>Subject Line</span>
                                        </label>
                                        <input
                                            id="emailSubject"
                                            type="text"
                                            value={emailSubject}
                                            onChange={(e) => setEmailSubject(e.target.value)}
                                            placeholder='e.g. URGENT: Your account has been compromised!'
                                        />
                                    </div>

                                    <div className="email-field">
                                        <label htmlFor="emailBody">
                                            <Terminal size={14} />
                                            <span>Email Body</span>
                                        </label>
                                        <textarea
                                            id="emailBody"
                                            value={emailBody}
                                            onChange={(e) => setEmailBody(e.target.value)}
                                            placeholder='Paste the full email body content here...'
                                            rows={8}
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        className="email-scan-btn"
                                        disabled={emailStatus === 'analyzing' || (!emailSender.trim() && !emailSubject.trim() && !emailBody.trim())}
                                    >
                                        <Send size={18} />
                                        <span>{emailStatus === 'analyzing' ? 'Analyzing...' : 'Scan for Threats'}</span>
                                    </button>
                                </form>
                            </div>

                            {/* EMAIL RESULTS */}
                            <div className="email-result-section">
                                <div className="section-header">
                                    <h2>Analysis Results</h2>
                                    <p>AI-powered phishing detection report</p>
                                </div>

                                <div className="email-result-card">
                                    {emailStatus === 'idle' && (
                                        <div className="state-empty">
                                            <div className="icon-ring">
                                                <Mail size={32} />
                                            </div>
                                            <h3>Paste an Email to Scan</h3>
                                            <p>Enter the sender, subject, and body of a suspicious email to analyze it for phishing threats</p>
                                        </div>
                                    )}

                                    {emailStatus === 'analyzing' && (
                                        <div className="state-analyzing">
                                            <div className="radar-spinner"></div>
                                            <h3>{emailLoadingMsg}</h3>
                                            <div className="target-url">
                                                {emailSender || 'Unknown Sender'}
                                            </div>
                                        </div>
                                    )}

                                    {(emailStatus === 'success' || emailStatus === 'error') && emailReport && (
                                        <div className="report-container">
                                            <div className="report-header">
                                                <div className="verdict-section">
                                                    <div className={`verdict-chip ${emailReport.verdict.toLowerCase()}`}>
                                                        {emailReport.verdict}
                                                    </div>
                                                    <p className="report-title">{emailReport.summary}</p>
                                                </div>
                                                <div className="risk-section">
                                                    <div className="risk-label">Phishing Score</div>
                                                    <div className="risk-value">
                                                        <span className="risk-val">{emailReport.risk_score}</span>
                                                        <span className="risk-max">/100</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <ThreatAnalysisReport report={emailReport} />

                                            <button
                                                className="scan-again-btn"
                                                onClick={() => {
                                                    setEmailStatus('idle')
                                                    setEmailReport(null)
                                                    setEmailSender('')
                                                    setEmailSubject('')
                                                    setEmailBody('')
                                                }}
                                            >
                                                Scan Another Email
                                            </button>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

            </main>
        </div>
    )
}

export default App
