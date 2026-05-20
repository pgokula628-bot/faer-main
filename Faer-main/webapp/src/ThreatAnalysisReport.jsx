/** Threat Analysis — detailed evidence, no internal tool names */

export default function ThreatAnalysisReport({ report }) {
    if (!report) return null

    const rules = report.rule_assessments || []
    const evidence = report.detailed_evidence || report.indicators || report.iocs || []

    return (
        <div className="threat-analysis-unified">
            <h2 className="threat-analysis-title">Threat Analysis</h2>

            <div className="test-results-strip">
                <div className="test-result-cell">
                    <span className="test-result-label">Verdict</span>
                    <span className="test-result-value">{report.verdict}</span>
                </div>
                <div className="test-result-cell">
                    <span className="test-result-label">Score</span>
                    <span className="test-result-value">{report.risk_score}/100</span>
                </div>
                <div className="test-result-cell">
                    <span className="test-result-label">Indicators</span>
                    <span className="test-result-value">{evidence.length}</span>
                </div>
                <div className="test-result-cell">
                    <span className="test-result-label">Rules Matched</span>
                    <span className="test-result-value">
                        {(report.rules_triggered || []).length ? report.rules_triggered.map(r => `R${r}`).join(', ') : 'None'}
                    </span>
                </div>
            </div>

            <div className="threat-analysis-body">
                {report.threat_analysis || report.explanation}
            </div>

            {report.verdict !== 'Safe' && report.why_unsafe?.length > 0 && (
                <div className="evidence-block unsafe-block">
                    <p className="evidence-block-title">Why this is unsafe</p>
                    <ul>
                        {report.why_unsafe.map((item, i) => (
                            <li key={i}>{item}</li>
                        ))}
                    </ul>
                </div>
            )}

            {report.why_safe?.length > 0 && (
                <div className="evidence-block safe-block">
                    <p className="evidence-block-title">Why this may be safe</p>
                    <ul>
                        {report.why_safe.map((item, i) => (
                            <li key={i}>{item}</li>
                        ))}
                    </ul>
                </div>
            )}

            {report.why_suspicious && (
                <p className="why-suspicious-block">{report.why_suspicious}</p>
            )}

            {rules.length > 0 && (
                <div className="rule-evidence-table-wrap">
                    <p className="evidence-block-title">Rule fit assessment (each rule: fits or does not fit)</p>
                    <table className="rule-evidence-table">
                        <thead>
                            <tr>
                                <th>Rule</th>
                                <th>Name</th>
                                <th>Fits?</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.map((r) => (
                                <tr key={r.rule_id} className={r.fits ? 'row-fits' : 'row-clear'}>
                                    <td>R{r.rule_id}</td>
                                    <td>{r.rule_name}</td>
                                    <td className={r.fits ? 'fit-yes' : 'fit-no'}>{r.fits ? 'YES' : 'NO'}</td>
                                    <td>{r.evidence}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {evidence.length > 0 && (
                <div className="detailed-evidence-grid">
                    <p className="evidence-block-title">Detailed evidence</p>
                    {evidence.map((item, i) => (
                        <div key={i} className="evidence-card">
                            <span className="ev-category">{item.category || item.type}</span>
                            <p className="ev-finding">{item.finding || item.value || item.detail}</p>
                            {item.implication && <p className="ev-implication">{item.implication}</p>}
                        </div>
                    ))}
                </div>
            )}

            {report.action && (
                <p className="threat-action-line">{report.action}</p>
            )}
        </div>
    )
}
