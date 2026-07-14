import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import type { Vulnerability } from '@/types';

interface AttackChainTabProps {
    vulnerabilities: Vulnerability[];
}

export default function AttackChainTab({ vulnerabilities }: AttackChainTabProps) {
    // Group findings that share the same attack_chain tag
    const chains = vulnerabilities.reduce<Record<string, Vulnerability[]>>((acc, v) => {
        if (v.attackChain) {
            const key = v.attackChain;
            (acc[key] = acc[key] || []).push(v);
        }
        return acc;
    }, {});

    const chainKeys = Object.keys(chains);

    if (chainKeys.length === 0) {
        return (
            <Card className="p-12 text-center">
                <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                <h3 className="text-xl font-semibold text-text-primary mb-2">No Attack Chains Detected</h3>
                <p className="text-text-secondary">No multi-step attack chains were identified in this scan.</p>
            </Card>
        );
    }

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    return (
        <div className="space-y-6">
            <p className="text-sm text-text-secondary">
                {chainKeys.length} attack chain{chainKeys.length !== 1 ? 's' : ''} detected — findings that can be combined to escalate impact.
            </p>

            {chainKeys.map((chainId) => {
                const steps = [...chains[chainId]].sort(
                    (a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9),
                );
                return (
                    <Card key={chainId} className="p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <svg className="w-5 h-5 text-status-high flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                            </svg>
                            <h3 className="text-lg font-semibold text-text-primary">
                                Attack Chain: <code className="text-accent-green font-mono text-sm ml-1">{chainId}</code>
                            </h3>
                            <Badge variant={steps[0]?.severity ?? 'info'} size="sm">
                                {steps.length} step{steps.length !== 1 ? 's' : ''}
                            </Badge>
                        </div>

                        {/* Chain visual */}
                        <div className="flex flex-col md:flex-row items-start md:items-center gap-0 md:gap-0 overflow-x-auto">
                            {steps.map((vuln, idx) => (
                                <div key={vuln.id} className="flex items-center gap-0 min-w-0">
                                    {/* Step node */}
                                    <div className={`
                                        flex-shrink-0 rounded-lg border p-3 min-w-[160px] max-w-[200px]
                                        ${vuln.severity === 'critical' ? 'border-status-critical bg-status-critical/5' :
                                          vuln.severity === 'high' ? 'border-status-high bg-status-high/5' :
                                          vuln.severity === 'medium' ? 'border-status-medium bg-status-medium/5' :
                                          'border-border-primary bg-bg-secondary'}
                                    `}>
                                        <div className="flex items-center gap-2 mb-1">
                                            <Badge variant={vuln.severity} size="sm">{vuln.severity}</Badge>
                                        </div>
                                        <div className="text-xs font-semibold text-text-primary line-clamp-2">{vuln.name}</div>
                                        {vuln.affectedUrl && (
                                            <div className="text-xs text-text-tertiary font-mono mt-1 truncate" title={vuln.affectedUrl}>
                                                {vuln.affectedUrl}
                                            </div>
                                        )}
                                    </div>
                                    {/* Arrow connector */}
                                    {idx < steps.length - 1 && (
                                        <div className="flex-shrink-0 px-2 text-text-tertiary text-xl">→</div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Impact statement */}
                        <div className="mt-4 p-3 bg-status-high/5 border border-status-high/20 rounded-lg">
                            <p className="text-xs text-text-secondary">
                                <span className="font-semibold text-status-high">Combined Impact:</span>{' '}
                                {steps.map((v) => v.name).join(' → ')} can be chained for full compromise.
                            </p>
                        </div>
                    </Card>
                );
            })}
        </div>
    );
}
