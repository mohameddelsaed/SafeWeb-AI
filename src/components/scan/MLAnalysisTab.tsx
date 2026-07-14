import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import type { MLResult, Vulnerability } from '@/types';

interface MLAnalysisTabProps {
    mlResult?: MLResult;
    vulnerabilities: Vulnerability[];
}

export default function MLAnalysisTab({ mlResult, vulnerabilities }: MLAnalysisTabProps) {
    const verifiedCount = vulnerabilities.filter((v) => v.verified).length;
    const fpFlagged = vulnerabilities.filter((v) => v.isFalsePositive).length;
    const highFPScore = vulnerabilities.filter((v) => (v.falsePositiveScore ?? 0) > 0.7);

    const predictionVariant = () => {
        if (!mlResult?.prediction) return 'info' as const;
        const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
            malicious: 'critical',
            phishing: 'high',
            suspicious: 'medium',
            benign: 'low',
        };
        return map[mlResult.prediction] ?? 'info';
    };

    if (!mlResult && vulnerabilities.length === 0) {
        return (
            <Card className="p-12 text-center">
                <p className="text-text-secondary">No ML analysis data available for this scan.</p>
            </Card>
        );
    }

    return (
        <div className="space-y-6">
            {/* ML Prediction Card */}
            {mlResult && (
                <Card className="p-6">
                    <h3 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
                        <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                        </svg>
                        ML Prediction
                    </h3>
                    <div className="flex items-center gap-6 mb-6">
                        <div>
                            <Badge variant={predictionVariant()} size="sm">
                                {mlResult.prediction?.toUpperCase() ?? 'N/A'}
                            </Badge>
                        </div>
                        {mlResult.modelUsed && (
                            <div className="text-sm text-text-tertiary">
                                Model: <span className="text-text-secondary font-mono">{mlResult.modelUsed}</span>
                            </div>
                        )}
                    </div>
                    {/* Confidence meter */}
                    {mlResult.confidence !== undefined && (
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm text-text-secondary">Confidence</span>
                                <span className="text-sm font-semibold text-accent-green">
                                    {Math.round(mlResult.confidence * 100)}%
                                </span>
                            </div>
                            <div className="h-3 bg-bg-secondary rounded-full overflow-hidden">
                                <div
                                    className="h-full rounded-full transition-all duration-700"
                                    style={{
                                        width: `${Math.round(mlResult.confidence * 100)}%`,
                                        backgroundColor: mlResult.confidence > 0.8 ? 'var(--color-accent-green, #22c55e)' :
                                            mlResult.confidence > 0.5 ? '#eab308' : '#ef4444',
                                    }}
                                />
                            </div>
                        </div>
                    )}
                    {mlResult.falsePositiveReduction !== undefined && (
                        <p className="text-sm text-text-secondary mt-4">
                            ML reduced false positives by{' '}
                            <span className="text-accent-green font-semibold">
                                {Math.round(mlResult.falsePositiveReduction * 100)}%
                            </span>{' '}
                            compared to raw scanner output.
                        </p>
                    )}
                </Card>
            )}

            {/* Verification Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="p-6 text-center">
                    <div className="text-3xl font-bold text-accent-green mb-2">{verifiedCount}</div>
                    <div className="text-sm text-text-tertiary">Verified Findings</div>
                    <div className="text-xs text-text-tertiary mt-1">Confirmed exploitable</div>
                </Card>
                <Card className="p-6 text-center">
                    <div className="text-3xl font-bold text-status-medium mb-2">{fpFlagged}</div>
                    <div className="text-sm text-text-tertiary">Marked False Positive</div>
                </Card>
                <Card className="p-6 text-center">
                    <div className="text-3xl font-bold text-status-high mb-2">{highFPScore.length}</div>
                    <div className="text-sm text-text-tertiary">High FP Risk (&gt;70%)</div>
                    <div className="text-xs text-text-tertiary mt-1">Needs review</div>
                </Card>
            </div>

            {/* High false-positive risk findings */}
            {highFPScore.length > 0 && (
                <Card className="p-6">
                    <h3 className="text-lg font-semibold text-text-primary mb-4">
                        High False-Positive Risk Findings
                    </h3>
                    <div className="space-y-3">
                        {highFPScore.map((vuln) => (
                            <div key={vuln.id} className="flex items-center gap-4 p-3 bg-bg-secondary rounded-lg">
                                <Badge variant={vuln.severity} size="sm">{vuln.severity}</Badge>
                                <span className="flex-1 text-sm text-text-primary">{vuln.name}</span>
                                <div className="text-right">
                                    <div className="text-xs text-text-tertiary">FP Score</div>
                                    <div className="text-sm font-semibold text-status-high">
                                        {Math.round((vuln.falsePositiveScore ?? 0) * 100)}%
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </Card>
            )}

            {/* Per-finding FP score histogram */}
            {vulnerabilities.some((v) => v.falsePositiveScore !== undefined) && (
                <Card className="p-6">
                    <h3 className="text-lg font-semibold text-text-primary mb-4">False-Positive Score Distribution</h3>
                    <div className="space-y-2">
                        {vulnerabilities
                            .filter((v) => v.falsePositiveScore !== undefined)
                            .sort((a, b) => (b.falsePositiveScore ?? 0) - (a.falsePositiveScore ?? 0))
                            .map((vuln) => (
                                <div key={vuln.id} className="flex items-center gap-3">
                                    <Badge variant={vuln.severity} size="sm">{vuln.severity[0].toUpperCase()}</Badge>
                                    <span className="text-sm text-text-secondary w-48 flex-shrink-0 truncate">{vuln.name}</span>
                                    <div className="flex-1 h-2 bg-bg-secondary rounded-full overflow-hidden">
                                        <div
                                            className="h-full rounded-full"
                                            style={{
                                                width: `${Math.round((vuln.falsePositiveScore ?? 0) * 100)}%`,
                                                backgroundColor: (vuln.falsePositiveScore ?? 0) > 0.7 ? '#ef4444' :
                                                    (vuln.falsePositiveScore ?? 0) > 0.4 ? '#eab308' : '#22c55e',
                                            }}
                                        />
                                    </div>
                                    <span className="text-xs text-text-tertiary w-10 text-right">
                                        {Math.round((vuln.falsePositiveScore ?? 0) * 100)}%
                                    </span>
                                </div>
                            ))}
                    </div>
                </Card>
            )}
        </div>
    );
}
