import { useState, useEffect } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { formatDateTime } from '@utils/date';
import { assetAPI } from '@/services/api';
import type { DiscoveredAsset, AssetMonitorRecord } from '@/types';

function SeverityIcon({ className = 'w-5 h-5' }: { className?: string }) {
    return (
        <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
    );
}

export default function AssetInventory() {
    const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
    const [records, setRecords] = useState<AssetMonitorRecord[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [tab, setTab] = useState<'assets' | 'changes'>('assets');
    const [acknowledging, setAcknowledging] = useState<string | null>(null);

    const fetchData = () => {
        Promise.all([
            assetAPI.getAll().then(({ data }) => Array.isArray(data) ? data : data.results ?? []),
            assetAPI.getMonitorRecords().then(({ data }) => Array.isArray(data) ? data : data.results ?? []),
        ]).then(([a, r]) => {
            setAssets(a);
            setRecords(r);
        }).finally(() => setIsLoading(false));
    };

    useEffect(() => { fetchData(); }, []);

    const handleAcknowledge = async (id: string) => {
        setAcknowledging(id);
        try {
            await assetAPI.acknowledgeRecord(id);
            fetchData();
        } finally {
            setAcknowledging(null);
        }
    };

    const unacknowledged = records.filter((r) => !r.acknowledged);

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Asset Inventory</h1>
                            <p className="text-text-secondary">Discovered assets and change monitoring for your targets.</p>
                        </div>
                        {unacknowledged.length > 0 && (
                            <div className="flex items-center gap-2 bg-status-high/10 border border-status-high/30 rounded-lg px-4 py-2">
                                <SeverityIcon className="w-4 h-4 text-status-high" />
                                <span className="text-sm text-status-high font-medium">{unacknowledged.length} unacknowledged change{unacknowledged.length > 1 ? 's' : ''}</span>
                            </div>
                        )}
                    </div>

                    {/* Tabs */}
                    <div className="flex border-b border-border-primary mb-6">
                        {(['assets', 'changes'] as const).map((t) => (
                            <button key={t} onClick={() => setTab(t)}
                                className={`px-5 py-3 text-sm font-medium capitalize border-b-2 transition-colors ${tab === t ? 'border-accent-green text-accent-green' : 'border-transparent text-text-secondary hover:text-text-primary'}`}>
                                {t}
                                {t === 'changes' && unacknowledged.length > 0 && (
                                    <span className="ml-2 inline-flex items-center justify-center w-5 h-5 rounded-full bg-status-high text-white text-xs">{unacknowledged.length}</span>
                                )}
                            </button>
                        ))}
                    </div>

                    {isLoading ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading assets…</span>
                        </div>
                    ) : tab === 'assets' ? (
                        assets.length === 0 ? (
                            <Card className="p-12 text-center">
                                <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
                                </svg>
                                <h3 className="text-xl font-semibold text-text-primary mb-2">No Assets Discovered</h3>
                                <p className="text-text-secondary">Assets are discovered automatically during scans.</p>
                            </Card>
                        ) : (
                            <div className="space-y-4">
                                {assets.map((asset) => (
                                    <Card key={asset.id} className="p-6">
                                        <div className="flex items-start justify-between">
                                            <div className="flex-1">
                                                <div className="flex items-center gap-3 mb-2">
                                                    <h3 className="font-mono font-medium text-text-primary">{asset.url}</h3>
                                                    <Badge variant={!asset.isActive ? 'info' : asset.isNew ? 'high' : 'low'} size="sm">
                                                        {asset.isNew ? 'new' : asset.isActive ? 'active' : 'inactive'}
                                                    </Badge>
                                                </div>
                                                <div className="flex flex-wrap gap-4 text-xs text-text-tertiary">
                                                    {asset.lastSeen && <span>Last seen: {formatDateTime(new Date(asset.lastSeen))}</span>}
                                                </div>
                                                {(asset.techStack ?? []).length > 0 && (
                                                    <div className="flex flex-wrap gap-1.5 mt-3">
                                                        {asset.techStack!.map((tech, i) => (
                                                            <span key={i} className="px-2 py-0.5 bg-bg-secondary rounded text-xs text-text-secondary">{tech}</span>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </Card>
                                ))}
                            </div>
                        )
                    ) : (
                        records.length === 0 ? (
                            <Card className="p-12 text-center">
                                <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                </svg>
                                <h3 className="text-xl font-semibold text-text-primary mb-2">No Change Records</h3>
                                <p className="text-text-secondary">Asset changes are tracked here automatically.</p>
                            </Card>
                        ) : (
                            <div className="space-y-4">
                                {records.map((record) => (
                                    <Card key={record.id} className={`p-5 ${!record.acknowledged ? 'border-status-high/30' : ''}`}>
                                        <div className="flex items-start justify-between">
                                            <div className="flex-1">
                                                <div className="flex items-center gap-3 mb-1">
                                                    {!record.acknowledged && <SeverityIcon className="w-4 h-4 text-status-high flex-shrink-0" />}
                                                    <span className="font-mono text-sm text-text-primary">{record.target}</span>
                                                    <Badge variant={record.changeType === 'new_subdomain' || record.changeType === 'new_port' || record.changeType === 'new_finding' ? 'high' : record.changeType === 'asset_gone' ? 'critical' : 'medium'} size="sm">
                                                        {record.changeType}
                                                    </Badge>
                                                </div>
                                                {record.detail && <p className="text-xs text-text-tertiary ml-7">{record.detail}</p>}
                                                <p className="text-xs text-text-tertiary ml-7 mt-1">{formatDateTime(new Date(record.detectedAt))}</p>
                                            </div>
                                            {!record.acknowledged && (
                                                <Button variant="outline" size="sm"
                                                    isLoading={acknowledging === record.id}
                                                    onClick={() => handleAcknowledge(record.id)}>
                                                    Acknowledge
                                                </Button>
                                            )}
                                        </div>
                                    </Card>
                                ))}
                            </div>
                        )
                    )}
                </Container>
            </div>
        </Layout>
    );
}
