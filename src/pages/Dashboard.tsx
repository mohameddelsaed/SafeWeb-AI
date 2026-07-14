import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';
import ScrollReveal from '@components/ui/ScrollReveal';
import { formatDateTime } from '@utils/date';
import { dashboardAPI, assetAPI, scheduledScanAPI } from '@/services/api';
import { useLanguage } from '@/contexts/LanguageContext';

// Icons for stat cards — defined outside component to avoid recreation on every render
const statIcons = [
  <svg key="scans" className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>,
  <svg key="critical" className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>,
  <svg key="score" className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
  <svg key="time" className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
];

export default function Dashboard() {
  const { t } = useLanguage();
  const [isLoading, setIsLoading] = useState(true);

  const [stats, setStats] = useState<{
    label: string; value: string; change: string; trend: 'up' | 'down' | 'neutral'; icon: React.ReactNode;
  }[]>([
    { label: 'Total Scans', value: '0', change: '', trend: 'neutral', icon: statIcons[0] },
    { label: 'Critical Issues', value: '0', change: '', trend: 'neutral', icon: statIcons[1] },
    { label: 'Security Score', value: '0', change: '', trend: 'neutral', icon: statIcons[2] },
    { label: 'Last Scan', value: 'N/A', change: '', trend: 'neutral', icon: statIcons[3] },
  ]);

  const [recentScans, setRecentScans] = useState<{
    id: string; target: string; type: string; status: string;
    date: Date; vulnerabilities: { critical: number; high: number; medium: number; low: number };
    score: number;
  }[]>([]);

  const [vulnerabilityOverview, setVulnerabilityOverview] = useState([
    { severity: 'critical' as const, count: 0, label: 'Critical' },
    { severity: 'high' as const, count: 0, label: 'High' },
    { severity: 'medium' as const, count: 0, label: 'Medium' },
    { severity: 'low' as const, count: 0, label: 'Low' },
  ]);

  interface TrendPoint { date: string; critical: number; high: number; medium: number; low: number; total: number }
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [assetChangeCount, setAssetChangeCount] = useState(0);
  const [scheduledActive, setScheduledActive] = useState(0);
  const [topCategories, setTopCategories] = useState<{ category: string; count: number }[]>([]);

  useEffect(() => {
    dashboardAPI.get()
      .then(({ data }) => {
        // Map stats from API
        if (data.stats) {
          setStats([
            { label: 'Total Scans', value: String(data.stats.totalScans ?? 0), change: data.stats.scansChange || '', trend: (data.stats.scansChange && data.stats.scansChange.startsWith('-')) ? 'down' as const : 'up' as const, icon: statIcons[0] },
            { label: 'Critical Issues', value: String(data.stats.criticalIssues ?? 0), change: data.stats.criticalChange || '', trend: (data.stats.criticalChange && !data.stats.criticalChange.startsWith('-')) ? 'up' as const : 'down' as const, icon: statIcons[1] },
            { label: 'Security Score', value: String(data.stats.securityScore ?? data.stats.avgScore ?? 0), change: data.stats.scoreChange || '', trend: (data.stats.scoreChange && data.stats.scoreChange.startsWith('-')) ? 'down' as const : 'up' as const, icon: statIcons[2] },
            { label: 'Last Scan', value: data.stats.lastScan || 'N/A', change: '', trend: 'neutral' as const, icon: statIcons[3] },
          ]);
        }

        // Map recent scans
        if (data.recentScans) {
          setRecentScans(data.recentScans.map((s: Record<string, unknown>) => ({
            id: s.id,
            target: s.target,
            type: s.scanType || s.type || 'Website',
            status: s.status,
            date: new Date(String(s.createdAt || s.date || new Date().toISOString())),
            vulnerabilities: s.vulnerabilitySummary || s.vulnerabilities || { critical: 0, high: 0, medium: 0, low: 0 },
            score: s.score || 0,
          })));
        }

        // Map vulnerability overview
        if (data.vulnerabilityOverview) {
          setVulnerabilityOverview([
            { severity: 'critical', count: data.vulnerabilityOverview.critical ?? 0, label: 'Critical' },
            { severity: 'high', count: data.vulnerabilityOverview.high ?? 0, label: 'High' },
            { severity: 'medium', count: data.vulnerabilityOverview.medium ?? 0, label: 'Medium' },
            { severity: 'low', count: data.vulnerabilityOverview.low ?? 0, label: 'Low' },
          ]);
        }
        // Top categories
        if (data.topCategories) {
          setTopCategories(data.topCategories.slice(0, 6));
        }
      })
      .catch((err) => {
        console.error('Dashboard load error:', err);
        setStats(prev => [{ ...prev[0], change: 'Error loading' }, ...prev.slice(1)]);
      });

      // Parallel: trends, asset changes, scheduled scans
      dashboardAPI.getTrends(14).then(({ data }) => {
        const arr: TrendPoint[] = Array.isArray(data)
          ? data
          : (data.dates ?? []).map((d: string, i: number) => ({
              date: d,
              critical: data.series?.critical?.[i] ?? 0,
              high: data.series?.high?.[i] ?? 0,
              medium: data.series?.medium?.[i] ?? 0,
              low: data.series?.low?.[i] ?? 0,
              total: (data.series?.total?.[i] ?? 0),
            }));
        setTrends(arr.slice(-14));
      }).catch(() => {});

      assetAPI.getMonitorRecords({ acknowledged: false }).then(({ data }) => {
        const arr = Array.isArray(data) ? data : data.results ?? [];
        setAssetChangeCount(arr.length);
      }).catch(() => {});

      scheduledScanAPI.getAll().then(({ data }) => {
        const arr = Array.isArray(data) ? data : data.results ?? [];
        setScheduledActive(arr.filter((s: { isActive: boolean }) => s.isActive).length);
      }).catch(() => {});

      // Resolve loading
      Promise.resolve().then(() => setIsLoading(false));
  }, []);

  return (
    <Layout>
      <div className="py-12">
        <Container>
          {/* Header */}
          <ScrollReveal>
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
            <div>
              <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                {t.dashboard.title}
              </h1>
              <p className="text-text-secondary">
                {t.dashboard.subtitle}
              </p>
            </div>
            <Link to="/scan">
              <Button variant="primary" className="mt-4 md:mt-0">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                {t.common.newScan}
              </Button>
            </Link>
          </div>
          </ScrollReveal>

          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
              <span className="ml-3 text-text-secondary">Loading dashboard...</span>
            </div>
          ) : (
          <>
          {/* Stats Grid */}
          <ScrollReveal stagger staggerDelay={80}>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {stats.map((stat, index) => {
              const translatedLabel = index === 0 ? t.dashboard.totalScans
                : index === 1 ? t.dashboard.criticalIssues
                : index === 2 ? t.dashboard.securityGrade
                : t.dashboard.lastScan;
              return (
              <Card key={index} className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green">
                    {stat.icon}
                  </div>
                  <span
                    className={`text-sm font-medium ${
                      stat.trend === 'up'
                        ? 'text-status-low'
                        : stat.trend === 'down'
                        ? 'text-status-critical'
                        : 'text-text-tertiary'
                    }`}
                  >
                    {stat.change}
                  </span>
                </div>
                <div className="text-3xl font-bold text-text-primary mb-1">
                  {stat.value}
                </div>
                <div className="text-sm text-text-tertiary">{translatedLabel}</div>
              </Card>
              );
            })}
          </div>
          </ScrollReveal>

          {/* ── Trends + Side Widgets ─────────────────────────── */}
          {trends.length > 0 && (() => {
            const maxVal = Math.max(...trends.map(t => t.total), 1);
            const W = 560; const H = 120; const barW = Math.floor(W / trends.length) - 2;
            return (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                <Card className="lg:col-span-2 p-6">
                  <div className="flex items-center justify-between mb-5">
                    <h2 className="text-lg font-heading font-semibold text-text-primary">Vulnerability Trends</h2>
                    <span className="text-xs text-text-tertiary">Last {trends.length} days</span>
                  </div>
                  <svg viewBox={`0 0 ${W + 8} ${H + 24}`} className="w-full" aria-label="Vulnerability trend bar chart">
                    {trends.map((pt, i) => {
                      const x = i * (barW + 2) + 4;
                      const totalH = Math.round((pt.total / maxVal) * H);
                      const critH = Math.round((pt.critical / maxVal) * H);
                      const highH = Math.round((pt.high / maxVal) * H);
                      const medH = Math.round((pt.medium / maxVal) * H);
                      const lowH = totalH - critH - highH - medH;
                      let y = H;
                      const segments = [
                        { h: lowH > 0 ? lowH : 0, fill: '#22c55e' },
                        { h: medH > 0 ? medH : 0, fill: '#f59e0b' },
                        { h: highH > 0 ? highH : 0, fill: '#f97316' },
                        { h: critH > 0 ? critH : 0, fill: '#ef4444' },
                      ];
                      return (
                        <g key={i}>
                          {segments.map((seg, si) => {
                            if (seg.h === 0) return null;
                            y -= seg.h;
                            return <rect key={si} x={x} y={y} width={barW} height={seg.h} fill={seg.fill} opacity={0.85} rx={1} />;
                          })}
                          {i % 3 === 0 && (
                            <text x={x + barW / 2} y={H + 16} textAnchor="middle" fontSize={8} fill="#6b7280">
                              {pt.date.slice(5)}
                            </text>
                          )}
                        </g>
                      );
                    })}
                    <line x1={0} y1={H} x2={W + 8} y2={H} stroke="#374151" strokeWidth={1} />
                  </svg>
                  <div className="flex gap-4 mt-3 text-xs text-text-tertiary">
                    {[['#ef4444','Critical'],['#f97316','High'],['#f59e0b','Medium'],['#22c55e','Low']].map(([c, l]) => (
                      <span key={l} className="flex items-center gap-1">
                        <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ background: c }} />
                        {l}
                      </span>
                    ))}
                  </div>
                </Card>

                <div className="flex flex-col gap-6">
                  {/* Asset Changes */}
                  <Card className="p-5 flex-1">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-text-primary">Asset Changes</h3>
                      <Link to="/assets" className="text-xs text-accent-green hover:underline">View</Link>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className={`w-12 h-12 rounded-full flex items-center justify-center font-bold text-xl ${assetChangeCount > 0 ? 'bg-status-high/15 text-status-high' : 'bg-status-low/15 text-status-low'}`}>
                        {assetChangeCount}
                      </div>
                      <p className="text-sm text-text-secondary">{assetChangeCount > 0 ? 'Unacknowledged changes detected' : 'All asset changes acknowledged'}</p>
                    </div>
                  </Card>

                  {/* Scheduled Scans */}
                  <Card className="p-5 flex-1">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-text-primary">Scheduled Scans</h3>
                      <Link to="/scheduled-scans" className="text-xs text-accent-green hover:underline">Manage</Link>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-full bg-accent-green/15 flex items-center justify-center font-bold text-xl text-accent-green">
                        {scheduledActive}
                      </div>
                      <p className="text-sm text-text-secondary">{scheduledActive} active schedule{scheduledActive !== 1 ? 's' : ''} running</p>
                    </div>
                  </Card>
                </div>
              </div>
            );
          })()}

          {/* ── Top Categories ─────────────────────────────────────── */}
          {topCategories.length > 0 && (
            <Card className="p-6 mb-8">
              <h2 className="text-lg font-heading font-semibold text-text-primary mb-4">Top Vulnerability Categories</h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {topCategories.map((cat) => {
                  const maxCat = Math.max(...topCategories.map(c => c.count), 1);
                  return (
                    <div key={cat.category} className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden mb-2">
                        <div className="h-full bg-accent-green rounded-full" style={{ width: `${(cat.count / maxCat) * 100}%` }} />
                      </div>
                      <p className="text-lg font-bold text-text-primary">{cat.count}</p>
                      <p className="text-xs text-text-tertiary truncate">{cat.category}</p>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Recent Scans */}
            <Card className="lg:col-span-2 p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-heading font-semibold text-text-primary">
                  Recent Scans
                </h2>
                <Link
                  to="/history"
                  className="text-sm text-accent-green hover:text-accent-green-hover transition-colors"
                >
                  View All
                </Link>
              </div>

              <div className="space-y-4">
                {recentScans.length === 0 && (
                  <div className="text-center py-12">
                    <svg className="w-16 h-16 mx-auto text-text-tertiary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">No scans yet</h3>
                    <p className="text-sm text-text-tertiary mb-4">Start your first security scan to see results here</p>
                    <Link to="/scan">
                      <Button variant="primary" size="sm">Start First Scan</Button>
                    </Link>
                  </div>
                )}
                {recentScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="p-4 rounded-lg bg-bg-secondary border border-border-primary hover:bg-bg-hover transition-colors duration-200"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="font-medium text-text-primary font-mono text-sm">
                            {scan.target}
                          </h3>
                          <Badge variant="default" size="sm">
                            {scan.type}
                          </Badge>
                          {scan.status === 'scanning' ? (
                            <Badge variant="info" size="sm">
                              Scanning...
                            </Badge>
                          ) : (
                            <Badge variant="low" size="sm">
                              Completed
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-text-tertiary">
                          {formatDateTime(scan.date)}
                        </p>
                      </div>
                      {scan.status === 'completed' && (
                        <div className="text-right">
                          <div className="text-2xl font-bold text-accent-green">
                            {scan.score}
                          </div>
                          <div className="text-xs text-text-tertiary">Score</div>
                        </div>
                      )}
                    </div>

                    {scan.status === 'completed' && (
                      <div className="flex items-center gap-4 text-xs">
                        {scan.vulnerabilities.critical > 0 && (
                          <span className="text-status-critical">
                            {scan.vulnerabilities.critical} Critical
                          </span>
                        )}
                        {scan.vulnerabilities.high > 0 && (
                          <span className="text-status-high">
                            {scan.vulnerabilities.high} High
                          </span>
                        )}
                        {scan.vulnerabilities.medium > 0 && (
                          <span className="text-status-medium">
                            {scan.vulnerabilities.medium} Medium
                          </span>
                        )}
                        {scan.vulnerabilities.low > 0 && (
                          <span className="text-status-low">
                            {scan.vulnerabilities.low} Low
                          </span>
                        )}
                      </div>
                    )}

                    {scan.status === 'scanning' && (
                      <div className="mt-2">
                        <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
                          <div className="h-full w-2/3 bg-accent-green animate-pulse"></div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>

            {/* Vulnerability Overview */}
            <Card className="p-6">
              <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                Vulnerabilities
              </h2>

              <div className="space-y-4">
                {vulnerabilityOverview.map((item) => (
                  <div key={item.severity}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge variant={item.severity} size="sm">
                          {item.label}
                        </Badge>
                      </div>
                      <span className="text-2xl font-bold text-text-primary">
                        {item.count}
                      </span>
                    </div>
                    <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          item.severity === 'critical'
                            ? 'bg-status-critical'
                            : item.severity === 'high'
                            ? 'bg-status-high'
                            : item.severity === 'medium'
                            ? 'bg-status-medium'
                            : 'bg-status-low'
                        }`}
                        style={{ width: `${Math.min((item.count / (Math.max(...vulnerabilityOverview.map(v => v.count), 1))) * 100, 100)}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-6 border-t border-border-primary">
                <Link to="/history">
                  <Button variant="outline" size="sm" className="w-full">
                    View Detailed Report
                  </Button>
                </Link>
              </div>
            </Card>
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/scan">
                <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4 group-hover:bg-accent-green/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Scan Website
                </h3>
                <p className="text-sm text-text-tertiary">
                  Perform comprehensive security analysis on any website or web application
                </p>
              </Link>
            </Card>

            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/learn">
                <div className="w-14 h-14 rounded-lg bg-accent-blue/10 flex items-center justify-center text-accent-blue mb-4 group-hover:bg-accent-blue/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Learn Security
                </h3>
                <p className="text-sm text-text-tertiary">
                  Access tutorials and best practices to strengthen your security knowledge
                </p>
              </Link>
            </Card>

            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/docs">
                <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4 group-hover:bg-accent-green/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Documentation
                </h3>
                <p className="text-sm text-text-tertiary">
                  Explore API documentation and integration guides for developers
                </p>
              </Link>
            </Card>
          </div>
          </>
          )}
        </Container>
      </div>
    </Layout>
  );
}
