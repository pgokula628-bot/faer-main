import { useState } from 'react'
import { UserPlus, LogIn, Shield, Eye, EyeOff, Check } from 'lucide-react'

export default function Register({ onRegister, onSwitchToLogin }) {
    const [name, setName] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [error, setError] = useState('')

    const handleSubmit = (e) => {
        e.preventDefault()
        setError('')

        // Validation
        if (password !== confirmPassword) {
            setError('Passwords do not match')
            return
        }

        if (password.length < 6) {
            setError('Password must be at least 6 characters')
            return
        }

        // Get existing users
        const users = JSON.parse(localStorage.getItem('threatlens_users') || '[]')

        // Check if email already exists
        if (users.find(u => u.email === email)) {
            setError('Email already registered')
            return
        }

        // Create new user
        const newUser = {
            id: Date.now().toString(),
            name,
            email,
            password,
            createdAt: new Date().toISOString()
        }

        // Save to localStorage
        users.push(newUser)
        localStorage.setItem('threatlens_users', JSON.stringify(users))
        localStorage.setItem('threatlens_current_user', JSON.stringify(newUser))

        onRegister(newUser)
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
                            <span>AI-powered real-time threat analysis</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Explainable security insights and reports</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Complete scan history and analytics</span>
                        </div>
                        <div className="feature-item">
                            <Check size={20} />
                            <span>Seamless browser integration</span>
                        </div>
                    </div>

                    <div className="info-quote">
                        <p>"Protect your digital presence with confidence. Join thousands of users securing their online experience."</p>
                    </div>
                </div>
            </div>

            {/* RIGHT SIDE - REGISTER FORM */}
            <div className="auth-form-panel">
                <div className="auth-card">
                    <div className="auth-header">
                        <h2>Get Started</h2>
                        <p>Create your account and start protecting yourself today</p>
                    </div>

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="name">Full Name</label>
                            <input
                                id="name"
                                type="text"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                placeholder="John Doe"
                                required
                            />
                        </div>

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

                        <div className="form-group">
                            <label htmlFor="confirmPassword">Confirm Password</label>
                            <input
                                id="confirmPassword"
                                type={showPassword ? 'text' : 'password'}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="••••••••"
                                required
                            />
                        </div>

                        {error && <div className="auth-error">{error}</div>}

                        <button type="submit" className="auth-submit">
                            <UserPlus size={18} />
                            <span>Create Account</span>
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>Already have an account?</p>
                        <button onClick={onSwitchToLogin} className="auth-link">
                            <LogIn size={16} />
                            <span>Sign in</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}
