import { useState, useEffect } from 'react'
import { Shield, Clock, LayoutDashboard, Terminal, AlertTriangle, Zap, Globe, ChevronRight, Activity, LogOut, User, Menu, X, Mail, Send, Inbox, AlertCircle, CheckCircle, MessageSquare } from 'lucide-react'
import Login from './Login'
import Register from './Register'
import { analyzeWebsite, analyzeEmail, analyzeChat } from './ruleEngine'
import { buildUnifiedThreatAnalysis, mergeFullReport } from './threatAnalysis'
import { fetchLiveThreatIntel, extractUrlsFromText } from './chromeThreatIntel'
import ThreatAnalysisReport from './ThreatAnalysisReport'

const getHistory = () => {
    try {
        const parsed = JSON.parse(localStorage.getItem('scan_history') || '[]')
        return Array.isArray(parsed) ? parsed : []
    } catch { return [] }
}
const saveHistory = (newItem) => {
    const current = getHistory()
    const updated = [newItem, ...current].slice(0, 500)
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

    // Chat Scanner State
    const [chatPlatform, setChatPlatform] = useState('whatsapp')
    const [chatSender, setChatSender] = useState('')
    const [chatMessage, setChatMessage] = useState('')
    const [chatStatus, setChatStatus] = useState('idle')
    const [chatReport, setChatReport] = useState(null)
    const [chatLoadingMsg, setChatLoadingMsg] = useState('Initializing Chat Scanner...')

    // Check for existing session and ensure demo user exists
    useEffect(() => {
        let users = []
        try {
            users = JSON.parse(localStorage.getItem('threatlens_users') || '[]')
            if (!Array.isArray(users)) users = []
        } catch { users = [] }

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

        // Clear stale cached reports from old scoring formula (one-time migration)
        const cacheVersion = localStorage.getItem('threatlens_cache_version')
        if (cacheVersion !== 'v6-clear-history-migration') {
            const keysToRemove = []
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i)
                if (key && key.startsWith('threat_cache_')) {
                    keysToRemove.push(key)
                }
            }
            keysToRemove.forEach(k => localStorage.removeItem(k))
            localStorage.removeItem('scan_history')
            localStorage.setItem('threatlens_cache_version', 'v6-clear-history-migration')
        }

        const currentUser = localStorage.getItem('threatlens_current_user')
        if (currentUser) {
            try {
                setUser(JSON.parse(currentUser))
            } catch {
                localStorage.removeItem('threatlens_current_user')
            }
        }
    }, [])

    // Analysis phase tracking
    const [analysisPhase, setAnalysisPhase] = useState('idle') // idle, gemini, rules, ml, done
    const [emailAnalysisPhase, setEmailAnalysisPhase] = useState('idle')
    const [chatAnalysisPhase, setChatAnalysisPhase] = useState('idle')

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
        if (chatStatus === 'analyzing') {
            const msgs = {
                live: ["Checking links against live blocklists...", "Verifying phone number reputation...", "Loading active threat feeds..."],
                gemini: ["Running deep chat analysis...", "Evaluating social engineering tactics...", "Building detailed evidence..."],
                rules: ["Applying strict phone number validation...", "Checking for crypto and investment scams...", "Scanning for urgency triggers..."],
                ml: ["Scoring message risk profile...", "Correlating live threat data...", "Finalizing assessment..."],
                ocr: ["Extracting text from screenshot...", "Running optical character recognition...", "Parsing chat transcript..."]
            }[chatAnalysisPhase] || ["Initializing chat scan..."]
            let i = 0
            const interval = setInterval(() => {
                setChatLoadingMsg(msgs[i % msgs.length])
                i++
            }, 600)
            return () => clearInterval(interval)
        }
    }, [chatStatus, chatAnalysisPhase])

    // Store pending URL params and process only after login
    const [pendingParams, setPendingParams] = useState(null)

    useEffect(() => {
        const params = new URLSearchParams(window.location.search)
        const typeParam = params.get('type')
        const urlParam = params.get('url')
        const textParam = params.get('text')
        const senderParam = params.get('sender') || ''
        const subjectParam = params.get('subject') || ''
        const bodyParam = params.get('body') || ''
        const messageParam = params.get('message') || ''

        // Always clean the URL
        if (typeParam || urlParam) {
            window.history.replaceState({}, document.title, "/")
        }

        // Store params for processing after login
        if (typeParam === 'website' && urlParam) {
            setPendingParams({ type: 'website', url: urlParam, text: textParam })
        } else if (typeParam === 'email') {
            setPendingParams({ type: 'email', sender: senderParam, subject: subjectParam, body: bodyParam })
        } else if (typeParam === 'chat') {
            setPendingParams({ type: 'chat', sender: senderParam, message: messageParam })
        } else if (urlParam) {
            setPendingParams({ type: 'website', url: urlParam, text: textParam })
        }
    }, [])

    // Process pending params only after user is authenticated
    useEffect(() => {
        if (!user || !pendingParams) return

        if (pendingParams.type === 'website') {
            setView('dashboard')
            setUrl(pendingParams.url)
            setStatus('analyzing')
            runAnalysis(pendingParams.url, pendingParams.text)
        } else if (pendingParams.type === 'email') {
            setView('email')
            setEmailSender(pendingParams.sender)
            setEmailSubject(pendingParams.subject)
            setEmailBody(pendingParams.body)
            if (pendingParams.sender || pendingParams.subject || pendingParams.body) {
                setTimeout(() => {
                    runEmailAnalysis(pendingParams.sender, pendingParams.subject, pendingParams.body)
                }, 100)
            }
        } else if (pendingParams.type === 'chat') {
            setView('chat')
            setChatSender(pendingParams.sender)
            setChatMessage(pendingParams.message)
            if (pendingParams.sender || pendingParams.message) {
                setTimeout(() => {
                    runChatAnalysis(pendingParams.sender, pendingParams.message)
                }, 100)
            }
        }
        setPendingParams(null)
    }, [user, pendingParams])


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

    const buildWebsiteGeminiPrompt = (targetUrl, targetText, ruleResult) => {
        const rulesSummary = JSON.stringify(ruleResult.rule_evaluations || [])
        return `You are a senior cybersecurity analyst. Write ONLY factual findings—never mention AI, machine learning, APIs, models, or software tools.

URL: ${targetUrl}
Page content: ${(targetText || '').substring(0, 4000)}
Security rule results: ${rulesSummary}

Provide three text fields (no tool names anywhere):
1) "opening_paragraph": 8–10 full sentences. Must start with "This website is suspicious because" OR "This website appears safe because". Cite main red flags with quoted facts from the URL.
2) "content_paragraph": exactly 4 sentences about page wording, forms, urgency, sensitive data requests, bad links.
3) "conclusion_paragraph": 3–5 sentences with final rating and clear user advice.

Also return "rule_assessments" for ALL 13 rules with fits true/false and one-sentence evidence each.

Return ONLY valid JSON:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "risk_score": 0-100,
  "summary": "short headline",
  "opening_paragraph": "8-10 sentences...",
  "content_paragraph": "4 sentences...",
  "conclusion_paragraph": "3-5 sentences...",
  "rule_assessments": [{"rule_id": 1, "rule_name": "HTTP vs HTTPS", "fits": true, "evidence": "one sentence"}],
  "action": "short advice"
}`
    }

    const buildEmailGeminiPrompt = (sender, subject, body, ruleResult) => {
        const rulesSummary = JSON.stringify(ruleResult.rule_evaluations || [])
        return `You are a senior cybersecurity analyst. Write ONLY factual findings—never mention AI, machine learning, APIs, models, or software tools.

Sender: ${sender}
Subject: ${subject}
Body: ${body.substring(0, 5000)}
Security rule results: ${rulesSummary}

Provide three text fields (no tool names):
1) "opening_paragraph": 8–10 sentences. Start with "This email is suspicious because" OR "This email appears safe because". Quote sender, subject, main threats.
2) "content_paragraph": exactly 4 sentences on body wording, links, urgency, credential requests.
3) "conclusion_paragraph": 3–5 sentences with final advice.

Return "rule_assessments" for ALL 14 rules with fits and evidence.

Return ONLY valid JSON:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "risk_score": 0-100,
  "summary": "short headline",
  "opening_paragraph": "8-10 sentences...",
  "content_paragraph": "4 sentences...",
  "conclusion_paragraph": "3-5 sentences...",
  "rule_assessments": [{"rule_id": 1, "rule_name": "Spoofed Sender", "fits": false, "evidence": "..."}],
  "action": "short advice"
}`
    }

    const buildChatGeminiPrompt = (sender, message, ruleResult, liveIntel) => {
        const rulesSummary = JSON.stringify(ruleResult.rule_evaluations || [])
        return `You are a senior cybersecurity analyst. Write ONLY factual findings—never mention AI, machine learning, APIs, models, or software tools.

Sender/Phone Number: ${sender}
Chat Message: ${message.substring(0, 5000)}
Live blocklist on links: ${liveIntel?.summary || 'unavailable'}
Security rule results: ${rulesSummary}

Provide three text fields (no tool names):
1) "opening_paragraph": 8–10 sentences. Start with "This chat message is suspicious because" OR "This chat message appears safe because". Quote sender, blocklist, main threats.
2) "content_paragraph": exactly 4 sentences on chat wording, links, urgency, investment/crypto fraud, credential requests.
3) "conclusion_paragraph": 3–5 sentences with final advice.

Return "rule_assessments" for ALL 14 rules with fits and evidence.

Return ONLY valid JSON:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "risk_score": 0-100,
  "summary": "short headline",
  "opening_paragraph": "8-10 sentences...",
  "content_paragraph": "4 sentences...",
  "conclusion_paragraph": "3-5 sentences...",
  "rule_assessments": [{"rule_id": 1, "rule_name": "Urgency Language Detection", "fits": false, "evidence": "..."}],
  "action": "short advice"
}`
    }

    const finalizeWebsiteReport = (targetUrl, targetText, gemini, rules, ml) => {
        const unified = buildUnifiedThreatAnalysis({
            gemini, rules, ml, targetLabel: 'website', maxRules: 13, targetId: targetUrl
        })
        return mergeFullReport({
            ...rules,
            url: targetUrl,
            summary: gemini?.summary || rules.summary,
            action: gemini?.action || rules.action,
            timestamp: new Date().toISOString()
        }, unified)
    }

    const finalizeEmailReport = (sender, gemini, rules, ml) => {
        const unified = buildUnifiedThreatAnalysis({
            gemini, rules, ml, targetLabel: 'email', maxRules: 14, targetId: sender
        })
        return mergeFullReport({
            ...rules,
            sender: sender,
            type: 'email',
            summary: gemini?.summary || rules.summary,
            action: gemini?.action || rules.action,
            timestamp: new Date().toISOString()
        }, unified)
    }

    const finalizeChatReport = (sender, gemini, rules, ml) => {
        const unified = buildUnifiedThreatAnalysis({
            gemini, rules, ml, targetLabel: 'chat message', maxRules: 14, targetId: sender
        })
        return mergeFullReport({
            ...rules,
            sender: sender,
            type: 'chat',
            summary: gemini?.summary || rules.summary,
            action: gemini?.action || rules.action,
            timestamp: new Date().toISOString()
        }, unified)
    }

    const runAnalysis = async (targetUrl, targetText) => {
        setStatus('analyzing')
        setAnalysisPhase('live')

        const cached = getCachedReport('website', targetUrl, targetText || '')
        if (cached?.analysis_mode === 'unified-v4') {
            setReport(cached)
            setHistory(saveHistory(cached))
            setAnalysisPhase('done')
            setStatus('success')
            return
        }

        try {
            setAnalysisPhase('gemini')
            let gemini = null
            try {
                const rulesPreview = analyzeWebsite(targetUrl, targetText || '')
                gemini = await callGeminiLLM(buildWebsiteGeminiPrompt(targetUrl, targetText, rulesPreview))
            } catch (e) {
                console.warn('Analysis API skipped:', e.message)
            }

            setAnalysisPhase('rules')
            await new Promise(r => setTimeout(r, 300))
            const rules = analyzeWebsite(targetUrl, targetText || '')

            setAnalysisPhase('ml')
            await new Promise(r => setTimeout(r, 300))
            let ml = null
            try {
                const mlResponse = await fetch('http://localhost:5000/api/analyze/url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: targetUrl, bodyText: targetText || '' })
                })
                if (mlResponse.ok) {
                    ml = await mlResponse.json()
                }
            } catch (e) {
                console.error('Python ML Backend disconnected or errored:', e)
            }

            const finalReport = finalizeWebsiteReport(targetUrl, targetText, gemini, rules, ml)
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
        if (cached?.analysis_mode === 'unified-v4') {
            setEmailReport(cached)
            setHistory(saveHistory(cached))
            setEmailAnalysisPhase('done')
            setEmailStatus('success')
            return
        }

        try {
            setEmailAnalysisPhase('gemini')
            let gemini = null
            try {
                const rulesPreview = analyzeEmail(useSender, useSubject, useBody)
                gemini = await callGeminiLLM(buildEmailGeminiPrompt(useSender, useSubject, useBody, rulesPreview))
            } catch (e) {
                console.warn('Analysis API skipped:', e.message)
            }

            setEmailAnalysisPhase('rules')
            await new Promise(r => setTimeout(r, 300))
            const rules = analyzeEmail(useSender, useSubject, useBody)

            setEmailAnalysisPhase('ml')
            await new Promise(r => setTimeout(r, 300))
            let ml = null
            try {
                const mlResponse = await fetch('http://localhost:5000/api/analyze/email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sender: useSender, subject: useSubject, body: useBody })
                })
                if (mlResponse.ok) {
                    ml = await mlResponse.json()
                }
            } catch (e) {
                console.error('Python ML Backend disconnected or errored:', e)
            }

            const finalReport = finalizeEmailReport(useSender, gemini, rules, ml)
            setCachedReport('email', useSender, useSubject + '||' + useBody, finalReport)
            setEmailReport(finalReport)
            setHistory(saveHistory(finalReport))
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

    const runChatAnalysis = async (directSender, directMessage) => {
        const useSender = directSender !== undefined ? directSender : chatSender
        const useMessage = directMessage !== undefined ? directMessage : chatMessage

        setChatStatus('analyzing')
        setChatAnalysisPhase('live')

        const cached = getCachedReport('chat', useSender, useMessage)
        if (cached?.analysis_mode === 'unified-v4') {
            setChatReport(cached)
            setHistory(saveHistory(cached))
            setChatAnalysisPhase('done')
            setChatStatus('success')
            return
        }

        try {
            setChatAnalysisPhase('gemini')
            let gemini = null
            try {
                const rulesPreview = analyzeChat(useSender, useMessage)
                gemini = await callGeminiLLM(buildChatGeminiPrompt(useSender, useMessage, rulesPreview))
            } catch (e) {
                console.warn('Analysis API skipped:', e.message)
            }

            setChatAnalysisPhase('rules')
            await new Promise(r => setTimeout(r, 300))
            const rules = analyzeChat(useSender, useMessage)

            setChatAnalysisPhase('ml')
            await new Promise(r => setTimeout(r, 300))
            let ml = null
            try {
                const mlResponse = await fetch('http://localhost:5000/api/analyze/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sender: useSender, message: useMessage })
                })
                if (mlResponse.ok) {
                    ml = await mlResponse.json()
                }
            } catch (e) {
                console.error('Python ML Backend disconnected or errored:', e)
            }

            const finalReport = finalizeChatReport(useSender, gemini, rules, ml)
            setCachedReport('chat', useSender, useMessage, finalReport)
            setChatReport(finalReport)
            setHistory(saveHistory(finalReport))
            setChatAnalysisPhase('done')
            setChatStatus('success')
        } catch (err) {
            console.error(err)
            setChatReport({
                verdict: 'Error',
                risk_score: 0,
                summary: 'Analysis Error',
                threat_analysis: err.message,
                action: 'Please try again.',
                indicators: []
            })
            setChatStatus('error')
            setChatAnalysisPhase('idle')
        }
    }

    const handleChatScan = (e) => {
        e.preventDefault()
        if (!chatSender.trim() && !chatMessage.trim()) return
        runChatAnalysis()
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
        safe: history.filter(h => h?.verdict === 'Safe').length,
        threats: history.filter(h => h?.verdict && h.verdict !== 'Safe').length
    }

    const renderTelemetry = (activeReport) => (
        <div className="cyber-telemetry-container">
            {activeReport && activeReport.components ? (
                <>
                    <div className="telemetry-card cyber-corners">
                        <div className="telemetry-card-title">
                            <Activity size={14} />
                            <span>Threat Engine Analysis</span>
                        </div>
                        <div className="telemetry-svg-wrap">
                            <svg viewBox="0 0 350 150" width="100%" height="100%">
                                <defs>
                                    <filter id="cyber-glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                                    </filter>
                                </defs>
                                <line x1="40" y1="30" x2="330" y2="30" stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
                                <line x1="40" y1="60" x2="330" y2="60" stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
                                <line x1="40" y1="90" x2="330" y2="90" stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
                                <line x1="40" y1="120" x2="330" y2="120" stroke="rgba(0, 210, 255, 0.2)" strokeWidth="1.5" />
                                
                                {(() => {
                                    const engines = [
                                        { name: 'Rules', score: activeReport.components.rules },
                                        { name: 'ML', score: activeReport.components.ml },
                                        { name: 'Open Source AI', score: activeReport.components.gemini }
                                    ]
                                    return engines.map((eng, i) => {
                                        const x = 85 + (i * 90)
                                        const h = Math.max(1, (eng.score / 100) * 80)
                                        const y = 120 - h
                                        return (
                                            <g key={eng.name}>
                                                <rect x={x - 12} y={y} width="24" height={h} fill="var(--accent-primary)" opacity="0.6" filter="url(#cyber-glow-cyan)" />
                                                <rect x={x - 12} y={y} width="24" height={h} fill="var(--accent-primary)" />
                                                <text x={x} y="138" textAnchor="middle" fill="var(--text-tertiary)" fontSize="10" fontFamily="Space Grotesk">{eng.name}</text>
                                                <text x={x} y={y - 6} textAnchor="middle" fill="var(--text-primary)" fontSize="10" fontFamily="Space Grotesk">{Math.round(eng.score)}</text>
                                            </g>
                                        )
                                    })
                                })()}
                            </svg>
                        </div>
                    </div>

                    <div className="telemetry-card cyber-corners">
                        <div className="telemetry-card-title">
                            <Shield size={14} />
                            <span>Target Safety Index</span>
                        </div>
                        <div className="telemetry-svg-wrap">
                            <svg viewBox="0 0 200 150" width="100%" height="100%">
                                <defs>
                                    <filter id="cyber-glow-dynamic" x="-20%" y="-20%" width="140%" height="140%">
                                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                                    </filter>
                                </defs>
                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="8" />
                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(0, 210, 255, 0.05)" strokeWidth="8" strokeDasharray="301.6" strokeDashoffset="0" />
                                <circle cx="100" cy="70" r="48" fill="none" 
                                    stroke={activeReport.risk_score >= 60 ? "var(--status-danger)" : activeReport.risk_score >= 30 ? "var(--status-warning)" : "var(--status-success)"} 
                                    strokeWidth="6" 
                                    strokeDasharray="301.6" 
                                    strokeDashoffset={301.6 - (301.6 * ((100 - activeReport.risk_score) / 100))}
                                    strokeLinecap="round"
                                    filter="url(#cyber-glow-dynamic)"
                                    transform="rotate(-90 100 70)"
                                />
                                <text x="100" y="68" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontWeight="700" fontFamily="Space Grotesk">
                                    {100 - activeReport.risk_score}%
                                </text>
                                <text x="100" y="85" textAnchor="middle" fill="var(--text-tertiary)" fontSize="8" fontWeight="600" style={{ textTransform: 'uppercase' }} letterSpacing="0.8" fontFamily="Inter">
                                    Safety Level
                                </text>
                            </svg>
                        </div>
                    </div>
                </>
            ) : (
                <>
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
                                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                                    </filter>
                                    <linearGradient id="cyber-area-cyan" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="var(--accent-primary)" stopOpacity="0.2" />
                                        <stop offset="100%" stopColor="var(--accent-primary)" stopOpacity="0.0" />
                                    </linearGradient>
                                </defs>
                                <line x1="20" y1="20" x2="330" y2="20" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                <line x1="20" y1="60" x2="330" y2="60" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                <line x1="20" y1="100" x2="330" y2="100" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
                                <line x1="20" y1="140" x2="330" y2="140" stroke="rgba(0, 210, 255, 0.12)" strokeWidth="1.5" />
                                <path d={(() => {
                                    const dPoints = history.length > 0 ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 })) : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                    return dPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
                                })()} fill="none" stroke="var(--accent-primary)" strokeWidth="2.5" filter="url(#cyber-glow-cyan)" />
                                <path d={(() => {
                                    const dPoints = history.length > 0 ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 })) : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                    const pathString = dPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
                                    return `${pathString} L ${dPoints[dPoints.length - 1].x} 140 L ${dPoints[0].x} 140 Z`;
                                })()} fill="url(#cyber-area-cyan)" />
                                {(() => {
                                    const dPoints = history.length > 0 ? [...history].reverse().slice(-7).map((h, i) => ({ x: 30 + i * 46, y: 130 - (h.risk_score || 0) * 0.9 })) : [{x:30,y:110},{x:76,y:90},{x:122,y:120},{x:168,y:60},{x:214,y:80},{x:260,y:40},{x:306,y:30}];
                                    return dPoints.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="3.5" fill="var(--bg-primary)" stroke="var(--accent-primary)" strokeWidth="2" />);
                                })()}
                            </svg>
                        </div>
                    </div>

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
                                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                                    </filter>
                                </defs>
                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="8" />
                                <circle cx="100" cy="70" r="48" fill="none" stroke="rgba(0, 210, 255, 0.05)" strokeWidth="8" strokeDasharray="301.6" strokeDashoffset="0" />
                                <circle cx="100" cy="70" r="48" fill="none" stroke="var(--accent-violet)" strokeWidth="6" 
                                    strokeDasharray="301.6" 
                                    strokeDashoffset={(() => { const ratio = stats.total > 0 ? stats.safe / stats.total : 0.85; return 301.6 - (301.6 * ratio); })()}
                                    strokeLinecap="round" filter="url(#cyber-glow-violet)" transform="rotate(-90 100 70)"
                                />
                                <text x="100" y="68" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontWeight="700" fontFamily="Space Grotesk">
                                    {(() => { const ratio = stats.total > 0 ? Math.round((stats.safe / stats.total) * 100) : 85; return `${ratio}%`; })()}
                                </text>
                                <text x="100" y="85" textAnchor="middle" fill="var(--text-tertiary)" fontSize="8" fontWeight="600" style={{ textTransform: 'uppercase' }} letterSpacing="0.8" fontFamily="Inter">
                                    Safe Ratio
                                </text>
                                <circle cx="100" cy="70" r="54" className="radial-pulse-glow" fill="none" stroke="var(--accent-primary)" strokeWidth="0.5" strokeDasharray="4 8" />
                            </svg>
                        </div>
                    </div>
                </>
            )}
        </div>
    )

    const renderSideSection = (activeReport, showHistory = true) => (
        <div className="side-section">
            {renderTelemetry(activeReport)}

            {showHistory && (
                <>
                    <div className="section-header">
                        <h2>Recent Activity</h2>
                        <p>Latest {history.length > 5 ? 5 : history.length} scans</p>
                    </div>

                    <div className="activity-list">
                        {history.slice(0, 5).map((h, i) => {
                            const isWeb = h.type === 'website' || h.url;
                            const isChat = h.type === 'chat';
                            const title = isWeb 
                                ? (() => { try { return new URL(h.url.startsWith('http') ? h.url : `https://${h.url}`).hostname } catch { return h.url || 'Unknown Website' } })()
                                : (h.sender || 'Unknown Sender');
                            
                            return (
                                <div key={i} className="activity-item">
                                    <div className="activity-icon">
                                        {isWeb ? <Globe size={14} /> : isChat ? <MessageSquare size={14} /> : <Mail size={14} />}
                                    </div>
                                    <div className="activity-details">
                                        <div className="activity-domain" style={{ wordBreak: 'break-all' }}>{title}</div>
                                        <div className="activity-time">{h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : 'Unknown Time'}</div>
                                    </div>
                                    <div className={`activity-badge ${h.verdict ? h.verdict.toLowerCase() : 'safe'}`}>{h.verdict || 'Safe'}</div>
                                </div>
                            );
                        })}
                        {history.length === 0 && (
                            <div className="empty-activity"><p>No recent scans</p></div>
                        )}
                    </div>
                </>
            )}
        </div>
    )

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
                        <span>Website Scan</span>
                    </button>
                    <button
                        className={`nav-link ${view === 'email' ? 'active' : ''}`}
                        onClick={() => { setView('email'); setMobileMenuOpen(false); }}
                    >
                        <Mail size={18} />
                        <span>Email Scan</span>
                    </button>
                    <button
                        className={`nav-link ${view === 'chat' ? 'active' : ''}`}
                        onClick={() => { setView('chat'); setMobileMenuOpen(false); }}
                    >
                        <MessageSquare size={18} />
                        <span>Chat Scan</span>
                    </button>
                    <button
                        className={`nav-link ${view === 'history' ? 'active' : ''}`}
                        onClick={() => { setView('history'); setMobileMenuOpen(false); }}
                    >
                        <Clock size={18} />
                        <span>Scan History</span>
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
                                <h1>Website Threat Scanner</h1>
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

                            {renderSideSection(report)}

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
                                {history.map((h, i) => {
                                    const isWeb = h.type === 'website' || h.url;
                                    const isChat = h.type === 'chat';
                                    const title = isWeb 
                                        ? (() => { try { return new URL(h.url.startsWith('http') ? h.url : `https://${h.url}`).hostname } catch { return h.url || 'Unknown Website' } })()
                                        : (h.sender || 'Unknown Sender');
                                    const scanLabel = isWeb ? 'Website Scan' : isChat ? 'Chat Scan' : 'Email Scan';

                                    return (
                                        <div
                                            key={i}
                                            className="history-card"
                                            onClick={() => {
                                                if (isWeb) {
                                                    setReport(h);
                                                    setStatus('success');
                                                    setView('dashboard');
                                                } else if (isChat) {
                                                    setChatReport(h);
                                                    setChatStatus('success');
                                                    setView('chat');
                                                } else {
                                                    setEmailReport(h);
                                                    setEmailStatus('success');
                                                    setView('email');
                                                }
                                            }}
                                        >
                                            <div className="card-header">
                                                <div className={`status-dot ${(h?.verdict || 'safe').toLowerCase()}`}></div>
                                                <span className="card-domain" style={{ wordBreak: 'break-all' }}>
                                                    {title}
                                                </span>
                                                <span className="card-badge" style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', marginLeft: 'auto' }}>
                                                    {scanLabel}
                                                </span>
                                            </div>
                                            <div className="card-summary">{h?.summary || 'Analysis Complete'}</div>
                                            <div className="card-footer">
                                                <span className="card-time">{h.timestamp ? new Date(h.timestamp).toLocaleString() : 'Unknown Time'}</span>
                                                <span className="card-score">Risk: {h.risk_score}/100</span>
                                            </div>
                                        </div>
                                    );
                                })}
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

                        <div className="email-scanner-content" style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 'var(--space-6)', alignItems: 'start' }}>
                            <div className="email-left-col" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
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

                                <div className="side-section" style={{ width: '100%' }}>
                                    {renderTelemetry(emailReport)}
                                </div>
                            </div>

                            <div className="email-right-col">
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
                                                        {emailReport.sender && (
                                                            <div className="report-sender-meta" style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '8px', borderLeft: '2.5px solid var(--accent-primary)', paddingLeft: '8px', wordBreak: 'break-all' }}>
                                                                Sender: <span style={{ color: 'var(--text-primary)', fontWeight: '500', fontFamily: 'Space Grotesk' }}>{emailReport.sender}</span>
                                                            </div>
                                                        )}
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
                    </div>
                )}

                {view === 'chat' && (
                    <div className="email-scanner-page">
                        <div className="page-header">
                            <div className="header-main">
                                <h1>Chat Threat Scanner</h1>
                                <p>Detect scams in WhatsApp, SMS, and Telegram messages</p>
                            </div>
                        </div>

                        <div className="email-scanner-content" style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 'var(--space-6)', alignItems: 'start' }}>
                            <div className="email-left-col" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
                                {/* CHAT INPUT FORM */}
                                <div className="email-form-section">
                                    <div className="section-header">
                                        <h2>Analyze Chat Message</h2>
                                        <p>Upload a screenshot for AI-powered scam detection</p>
                                    </div>

                                    <form onSubmit={handleChatScan} className="email-form-card">
                                        <div className="email-field">
                                            <label htmlFor="chatSender">
                                                <User size={14} />
                                                <span>Sender</span>
                                            </label>
                                            <input
                                                id="chatSender"
                                                type="text"
                                                value={chatSender}
                                                readOnly
                                                placeholder='No sender detected'
                                                style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}
                                            />
                                        </div>
                                        
                                        <div className="email-field">
                                            <label htmlFor="chatMessage">
                                                <MessageSquare size={14} />
                                                <span>Extracted Message Content</span>
                                            </label>
                                            <textarea
                                                id="chatMessage"
                                                value={chatMessage}
                                                readOnly
                                                placeholder='No text selected. Please highlight text and use the Chrome Extension.'
                                                rows={5}
                                                style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}
                                            />
                                        </div>

                                        <button
                                            type="submit"
                                            className="email-scan-btn"
                                            disabled={chatStatus === 'analyzing' || !chatSender.trim() || !chatMessage.trim()}
                                        >
                                            <Send size={18} />
                                            <span>{chatStatus === 'analyzing' ? 'Analyzing...' : 'Scan Chat Message'}</span>
                                        </button>
                                    </form>
                                </div>

                                <div className="side-section" style={{ width: '100%' }}>
                                    {renderTelemetry(chatReport)}
                                </div>
                            </div>

                            <div className="email-right-col">
                                {/* CHAT RESULTS */}
                                <div className="email-result-section">
                                    <div className="section-header">
                                        <h2>Analysis Results</h2>
                                        <p>AI-powered scam detection report</p>
                                    </div>

                                    <div className="email-result-card">
                                        {chatStatus === 'idle' && (
                                            <div className="state-empty">
                                                <div className="icon-ring">
                                                    <MessageSquare size={32} />
                                                </div>
                                                <h3>Analyze a Chat Message</h3>
                                                <p>Highlight text in WhatsApp Web or Telegram Web and click "Scan Chat" from the Chrome Extension.</p>
                                            </div>
                                        )}

                                        {chatStatus === 'analyzing' && (
                                            <div className="state-analyzing">
                                                <div className="radar-spinner"></div>
                                                <h3>{chatLoadingMsg}</h3>
                                                <div className="target-url">
                                                    {chatSender || 'Unknown Sender'}
                                                </div>
                                            </div>
                                        )}

                                        {(chatStatus === 'success' || chatStatus === 'error') && chatReport && (
                                            <div className="report-container">
                                                <div className="report-header">
                                                    <div className="verdict-section">
                                                        <div className={`verdict-chip ${chatReport.verdict.toLowerCase()}`}>
                                                            {chatReport.verdict}
                                                        </div>
                                                        <p className="report-title">{chatReport.summary}</p>
                                                        {chatReport.sender && (
                                                            <div className="report-sender-meta" style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '8px', borderLeft: '2.5px solid var(--accent-primary)', paddingLeft: '8px', wordBreak: 'break-all' }}>
                                                                Sender: <span style={{ color: 'var(--text-primary)', fontWeight: '500', fontFamily: 'Space Grotesk' }}>{chatReport.sender}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="risk-section">
                                                        <div className="risk-label">Threat Score</div>
                                                        <div className="risk-value">
                                                            <span className="risk-val">{chatReport.risk_score}</span>
                                                            <span className="risk-max">/100</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <ThreatAnalysisReport report={chatReport} />

                                                <button
                                                    className="scan-again-btn"
                                                    onClick={() => {
                                                        setChatStatus('idle')
                                                        setChatReport(null)
                                                        setChatSender('')
                                                        setChatMessage('')
                                                        const fileInput = document.getElementById('chatImageUpload')
                                                        if(fileInput) fileInput.value = ''
                                                    }}
                                                >
                                                    Scan Another Message
                                                </button>
                                            </div>
                                        )}
                                    </div>
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
