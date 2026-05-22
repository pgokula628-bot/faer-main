/** Opening paragraph → green/red rule box → content → conclusion (no sub-headings) */

export default function ThreatAnalysisReport({ report }) {
    if (!report) return null

    const opening = report.opening_paragraph || ''
    const content = report.content_paragraph || ''
    const conclusion = report.conclusion_paragraph || ''
    const rules = report.rule_assessments || []

    const fits = rules.filter(r => r.fits)
    const notFits = rules.filter(r => !r.fits)

    return (
        <div className="threat-analysis-unified">
            <div className="threat-analysis-body">
                {opening && (
                    <p className="analysis-para analysis-opening">{opening}</p>
                )}

                {rules.length > 0 && (
                    <div className="rules-evidence-box">
                        {fits.map((r) => (
                            <div key={`fit-${r.rule_id}`} className="rule-line rule-fits">
                                <span className="rule-line-badge">Fits</span>
                                <span className="rule-line-text">
                                    <strong>Rule {r.rule_id} — {r.rule_name}.</strong> {r.evidence}
                                </span>
                            </div>
                        ))}
                        {notFits.map((r) => (
                            <div key={`clear-${r.rule_id}`} className="rule-line rule-not-fits">
                                <span className="rule-line-badge">Does not fit</span>
                                <span className="rule-line-text">
                                    <strong>Rule {r.rule_id} — {r.rule_name}.</strong> {r.evidence}
                                </span>
                            </div>
                        ))}
                    </div>
                )}

                {content && (
                    <p className="analysis-para analysis-content">{content}</p>
                )}

                {conclusion && (
                    <p className="analysis-para analysis-conclusion">{conclusion}</p>
                )}
            </div>
        </div>
    )
}
