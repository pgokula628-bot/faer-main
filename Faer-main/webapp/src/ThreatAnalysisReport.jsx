/** Analysis only: 3–4 paragraphs, no sub-headings */

export default function ThreatAnalysisReport({ report }) {
    if (!report) return null

    const paragraphs = report.analysis_paragraphs?.length
        ? report.analysis_paragraphs
        : (report.threat_analysis || report.explanation || '').split(/\n\n+/).filter(Boolean)

    return (
        <div className="threat-analysis-unified">
            <div className="threat-analysis-body">
                {paragraphs.map((para, i) => (
                    <p key={i} className="analysis-para">{para.trim()}</p>
                ))}
            </div>
        </div>
    )
}
