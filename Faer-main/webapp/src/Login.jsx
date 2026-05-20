import { useState } from 'react'
import { LogIn, UserPlus, Shield, Eye, EyeOff, Check, Zap, Lock } from 'lucide-react'

export default function Login({ onLogin, onSwitchToRegister }) {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [error, setError] = useState('')

    const useDemoAccount = () => {
        setEmail('demo@threatlens.ai')
        setPassword('demo123')
    }

    const handleSubmit = (e) => {
        e.preventDefault()
        setError('')

        // Get users from localStorage
        const users = JSON.parse(localStorage.getItem('threatlens_users') || '[]')

        // Find user
        const user = users.find(u => u.email === email && u.password === password)

        if (user) {
            // Store current user
            localStorage.setItem('threatlens_current_user', JSON.stringify(user))
            onLogin(user)
        } else {
            setError('Invalid email or password')
        }
    }

    return (
        <div className="auth-layout">
            {/* LEFT SIDE - INFO PANEL */}
            <div className="auth-info-panel">
                <div className="info-content">
                    <div className="info-logo">
                        <Shield size={48} />
                    </div>
                    <h1>Threat Lens</h1>
                    <p className="info-tagline">Advanced Threat Detection Platform</p>

                    <div className="info-features">
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Real-time phishing detection powered by AI</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Comprehensive threat analysis and reporting</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Historical scan tracking and insights</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Browser extension for instant security checks</span>
                        </div>
                    </div>

                    <div className="info-stats">
                        <div className="stat-item">
                            <div className="stat-value">10K+</div>
                            <div className="stat-label">Threats Detected</div>
                        </div>
                        <div className="stat-item">
                            <div className="stat-value">99.8%</div>
                            <div className="stat-label">Accuracy Rate</div>
                        </div>
                        <div className="stat-item">
                            <div className="stat-value">24/7</div>
                            <div className="stat-label">Protection</div>
                        </div>
                    </div>
                </div>
            </div>

            {/* RIGHT SIDE - LOGIN FORM */}
            <div className="auth-form-panel">
                <div className="auth-card">
                    <div className="auth-header">
                        <h2>Welcome Back</h2>
                        <p>Sign in to continue protecting your digital presence</p>
                    </div>

                    {/* DEMO CREDENTIALS BANNER */}
                    <div className="demo-banner">
                        <Lock size={16} />
                        <div className="demo-text">
                            <strong>Demo Account:</strong> demo@threatlens.ai / demo123
                        </div>
                        <button type="button" onClick={useDemoAccount} className="demo-fill-btn">
                            <Zap size={14} />
                            Auto-fill
                        </button>
                    </div>

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="email">Email</label>
                            <input
                                id="email"
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="you@example.com"
                                required
                            />
                        </div>

                        <div className="form-group">
                            <label htmlFor="password">Password</label>
                            <div className="password-input">
                                <input
                                    id="password"
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                    required
                                />
                                <button
                                    type="button"
                                    className="password-toggle"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                </button>
                            </div>
                        </div>

                        {error && <div className="auth-error">{error}</div>}

                        <button type="submit" className="auth-submit">
                            <LogIn size={18} />
                            <span>Sign In</span>
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>Don't have an account?</p>
                        <button onClick={onSwitchToRegister} className="auth-link">
                            <UserPlus size={16} />
                            <span>Create account</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}
