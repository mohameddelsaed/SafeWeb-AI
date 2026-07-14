import { useState } from 'react';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import type { ReconData } from '@/types';

interface ReconTabProps {
    reconData?: ReconData;
}

/* ── tiny helpers ────────────────────────────────────────────── */

/** Safely coerce a value to string for rendering */
function str(v: unknown): string {
    if (v === null || v === undefined) return '—';
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    return JSON.stringify(v);
}

/** Collapsible section wrapper */
function Section({ title, icon, children, defaultOpen = true }: {
    title: string; icon: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean;
}) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <Card className="p-6">
            <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between text-left">
                <h3 className="text-lg font-semibold text-text-primary flex items-center gap-2">
                    {icon}{title}
                </h3>
                <svg className={`w-5 h-5 text-text-tertiary transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
            </button>
            {open && <div className="mt-4">{children}</div>}
        </Card>
    );
}

const iconCode = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
);
const iconShield = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);
const iconLock = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
);
const iconGlobe = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
    </svg>
);
const iconMail = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
);
const iconCloud = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
    </svg>
);
const iconChart = (
    <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6m6 0h6m-6 0V9a2 2 0 012-2h2a2 2 0 012 2v10m6 0v-4a2 2 0 00-2-2h-2a2 2 0 00-2 2v4" />
    </svg>
);

/* ── main component ─────────────────────────────────────────── */

export default function ReconTab({ reconData }: ReconTabProps) {
    if (!reconData || Object.keys(reconData).length === 0) {
        return (
            <Card className="p-12 text-center">
                <p className="text-text-secondary">No recon data available for this scan.</p>
            </Card>
        );
    }

    // ── Extract data from backend structure ──
    // Each module: { findings, metadata, errors, stats, issues, ...specific }
    const techMod   = reconData.technologies ?? reconData.tech_stack;
    const wafMod    = reconData.waf;
    const certMod   = reconData.certificate ?? reconData.ssl;
    const subsMod   = reconData.passiveSubdomains ?? reconData.passive_subdomains;
    const headerMod = reconData.headers;
    const cookieMod = reconData.cookies;
    const emailMod  = reconData.emails;
    const socialMod = reconData.social;
    const cloudMod  = reconData.cloud;
    const corsMod   = reconData.cors;
    const cmsMod    = reconData.cms;
    const whoisMod  = reconData.whois;
    const attackSurface = reconData.attackSurface ?? reconData.attack_surface;
    const riskScore = reconData.riskScore ?? reconData.risk_score;
    const stats     = reconData._stats;

    // ── Safely pull out usable data from each module ──
    const technologies: Array<{ name: string; category?: string; version?: string; confidence?: string; source?: string }> =
        (techMod?.technologies ?? techMod?.techStack ?? (Array.isArray(techMod) ? techMod : []));

    const wafDetected: boolean = wafMod?.detected ?? false;
    const wafName: string | undefined = wafMod?.name ?? wafMod?.product;

    const cert = certMod ?? {};
    const hasSsl: boolean = cert.hasSsl ?? cert.has_ssl ?? false;
    const certIssuer: string | undefined = cert.issuer;
    const certSubject: string | undefined = cert.subject ?? cert.hostname;
    const certNotAfter: string | undefined = cert.notAfter ?? cert.not_after;
    const certSelfSigned: boolean = cert.selfSigned ?? cert.self_signed ?? false;
    const certDaysUntilExpiry: number | undefined = cert.daysUntilExpiry ?? cert.days_until_expiry;

    const subdomains: string[] = subsMod?.subdomains ?? (Array.isArray(subsMod) ? subsMod : []);

    // Headers: the module wraps them; extract the header list or map
    const headerPresent = headerMod?.present ?? headerMod?.headers;
    const headerMap: Record<string, string> = {};
    if (Array.isArray(headerPresent)) {
        for (const h of headerPresent) {
            if (typeof h === 'string') {
                headerMap[h] = 'present';
            } else if (h && typeof h === 'object') {
                headerMap[h.name ?? h.header ?? 'unknown'] = h.value ?? str(h);
            }
        }
    } else if (headerPresent && typeof headerPresent === 'object') {
        Object.assign(headerMap, headerPresent);
    }
    // Also check for missing security headers in the module's issues
    const headerIssues: Array<{header?: string; severity?: string; description?: string}> =
        (headerMod?.issues ?? headerMod?.missing ?? []).filter((i: unknown) => i && typeof i === 'object');

    const cookies: Array<{ name: string; httpOnly?: boolean; secure?: boolean; sameSite?: string }> =
        cookieMod?.cookies ?? (Array.isArray(cookieMod) ? cookieMod : []);

    const emails: Array<{ address?: string; source?: string; confidence?: string }> =
        (emailMod?.emails ?? (Array.isArray(emailMod) ? emailMod : []));

    const socialProfiles: Array<{ platform?: string; url?: string }> =
        socialMod?.socialProfiles ?? socialMod?.social_profiles ?? (Array.isArray(socialMod) ? socialMod : []);

    const cloudProviders: Array<{ name?: string; confidence?: string }> =
        cloudMod?.providers ?? (cloudMod?.provider ? [{ name: cloudMod.provider }] : []);
    const corsVulnerable: boolean = corsMod?.vulnerable ?? false;
    const cmsDetected: string | undefined = cmsMod?.cms;

    const overallScore: number | undefined = riskScore?.overallScore ?? riskScore?.overall_score;

    return (
        <div className="space-y-6">
            {/* ── Risk Score ── */}
            {overallScore !== undefined && (
                <Card className="p-6">
                    <div className="flex items-center gap-4">
                        {iconChart}
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">Overall Recon Risk Score</div>
                            <span className={`text-3xl font-bold ${overallScore >= 70 ? 'text-status-critical' : overallScore >= 40 ? 'text-status-high' : 'text-accent-green'}`}>
                                {overallScore}
                            </span>
                            <span className="text-text-tertiary text-sm ml-1">/ 100</span>
                        </div>
                    </div>
                </Card>
            )}

            {/* ── Technologies ── */}
            {technologies.length > 0 && (
                <Section title={`Technology Stack (${technologies.length})`} icon={iconCode}>
                    <div className="flex flex-wrap gap-2">
                        {technologies.map((tech, i) => {
                            const name = typeof tech === 'string' ? tech : tech.name;
                            const cat  = typeof tech === 'string' ? undefined : tech.category;
                            return (
                                <span key={i} className="px-3 py-1.5 bg-accent-green/10 text-accent-green rounded-full text-sm font-mono flex items-center gap-1.5">
                                    {name}
                                    {cat && <span className="text-xs text-text-tertiary">({cat})</span>}
                                </span>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── WAF Detection ── */}
            {wafMod && (
                <Section title="WAF Detection" icon={iconShield}>
                    <div className="flex items-center gap-4">
                        <Badge variant={wafDetected ? 'low' : 'critical'}>
                            {wafDetected ? 'WAF Detected' : 'No WAF'}
                        </Badge>
                        {wafName && <span className="text-text-primary font-semibold">{wafName}</span>}
                    </div>
                </Section>
            )}

            {/* ── SSL / Certificate ── */}
            {certMod && (
                <Section title="SSL / TLS Certificate" icon={iconLock}>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">SSL Present</div>
                            <Badge variant={hasSsl ? 'low' : 'critical'}>{hasSsl ? 'Yes' : 'No'}</Badge>
                        </div>
                        {certIssuer && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">Issuer</div>
                                <div className="text-sm text-text-primary">{certIssuer}</div>
                            </div>
                        )}
                        {certSubject && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">Subject</div>
                                <div className="text-sm text-text-primary font-mono">{certSubject}</div>
                            </div>
                        )}
                        {certNotAfter && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">Expires</div>
                                <div className="text-sm text-text-primary font-mono">{new Date(certNotAfter).toLocaleDateString()}</div>
                            </div>
                        )}
                        {certDaysUntilExpiry !== undefined && certDaysUntilExpiry !== null && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">Days Until Expiry</div>
                                <span className={`font-bold ${certDaysUntilExpiry < 30 ? 'text-status-critical' : 'text-accent-green'}`}>
                                    {certDaysUntilExpiry}
                                </span>
                            </div>
                        )}
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">Self-Signed</div>
                            <Badge variant={certSelfSigned ? 'critical' : 'low'}>
                                {certSelfSigned ? 'Yes' : 'No'}
                            </Badge>
                        </div>
                    </div>
                </Section>
            )}

            {/* ── CMS ── */}
            {cmsDetected && (
                <Section title="CMS Detection" icon={iconCode}>
                    <span className="px-3 py-1.5 bg-accent-green/10 text-accent-green rounded-full text-sm font-mono">
                        {cmsDetected}
                    </span>
                </Section>
            )}

            {/* ── CORS ── */}
            {corsMod && (
                <Section title="CORS Configuration" icon={iconShield}>
                    <Badge variant={corsVulnerable ? 'critical' : 'low'}>
                        {corsVulnerable ? 'Vulnerable' : 'Properly Configured'}
                    </Badge>
                </Section>
            )}

            {/* ── Cloud Provider ── */}
            {cloudProviders.length > 0 && (
                <Section title="Cloud Infrastructure" icon={iconCloud}>
                    <div className="flex flex-wrap gap-2">
                        {cloudProviders.map((p, i) => (
                            <span key={i} className="px-3 py-1.5 bg-accent-green/10 text-accent-green rounded-full text-sm font-mono flex items-center gap-1.5">
                                {p.name ?? str(p)}
                                {p.confidence && <span className="text-xs text-text-tertiary">({p.confidence})</span>}
                            </span>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Subdomains ── */}
            {subdomains.length > 0 && (
                <Section title={`Discovered Subdomains (${subdomains.length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                        {subdomains.map((sub, i) => (
                            <code key={i} className="text-sm text-accent-green font-mono bg-bg-secondary px-3 py-1.5 rounded">
                                {typeof sub === 'string' ? sub : str(sub)}
                            </code>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Security Headers ── */}
            {(Object.keys(headerMap).length > 0 || headerIssues.length > 0) && (
                <Section title="Security Headers" icon={iconShield} defaultOpen={false}>
                    {Object.keys(headerMap).length > 0 && (
                        <div className="space-y-2 max-h-64 overflow-y-auto mb-4">
                            {Object.entries(headerMap).map(([key, val]) => (
                                <div key={key} className="flex items-start gap-3 text-sm">
                                    <span className="font-mono text-text-tertiary w-64 flex-shrink-0">{key}:</span>
                                    <span className="font-mono text-text-secondary break-all">{str(val)}</span>
                                </div>
                            ))}
                        </div>
                    )}
                    {headerIssues.length > 0 && (
                        <>
                            <div className="text-sm font-semibold text-text-secondary mb-2">Missing / Misconfigured Headers</div>
                            <div className="space-y-1.5">
                                {headerIssues.map((issue, i) => (
                                    <div key={i} className="flex items-center gap-2 text-sm">
                                        <Badge variant={issue.severity === 'high' ? 'high' : issue.severity === 'medium' ? 'medium' : 'low'} size="sm">
                                            {issue.severity ?? 'info'}
                                        </Badge>
                                        <span className="font-mono text-text-primary">{issue.header ?? str(issue)}</span>
                                    </div>
                                ))}
                            </div>
                        </>
                    )}
                </Section>
            )}

            {/* ── Cookies ── */}
            {cookies.length > 0 && (
                <Section title={`Cookies (${cookies.length})`} icon={iconShield} defaultOpen={false}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-border-primary">
                                    <th className="text-left py-2 pr-4 text-text-tertiary font-medium">Name</th>
                                    <th className="text-center py-2 pr-4 text-text-tertiary font-medium">HttpOnly</th>
                                    <th className="text-center py-2 pr-4 text-text-tertiary font-medium">Secure</th>
                                    <th className="text-left py-2 text-text-tertiary font-medium">SameSite</th>
                                </tr>
                            </thead>
                            <tbody>
                                {cookies.map((cookie, i) => (
                                    <tr key={i} className="border-b border-border-primary/30">
                                        <td className="py-2 pr-4 font-mono text-text-primary">{cookie.name ?? '—'}</td>
                                        <td className="py-2 pr-4 text-center">
                                            <Badge variant={cookie.httpOnly ? 'low' : 'high'} size="sm">
                                                {cookie.httpOnly ? '✓' : '✗'}
                                            </Badge>
                                        </td>
                                        <td className="py-2 pr-4 text-center">
                                            <Badge variant={cookie.secure ? 'low' : 'high'} size="sm">
                                                {cookie.secure ? '✓' : '✗'}
                                            </Badge>
                                        </td>
                                        <td className="py-2 text-text-secondary">{cookie.sameSite ?? '—'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </Section>
            )}

            {/* ── Emails ── */}
            {emails.length > 0 && (
                <Section title={`Discovered Emails (${emails.length})`} icon={iconMail} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {emails.map((em, i) => {
                            const addr = typeof em === 'string' ? em : em.address ?? str(em);
                            const src  = typeof em === 'string' ? undefined : em.source;
                            return (
                                <div key={i} className="flex items-center gap-3 text-sm">
                                    <span className="font-mono text-text-primary">{addr}</span>
                                    {src && <span className="text-xs text-text-tertiary">({src})</span>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── Social Profiles ── */}
            {socialProfiles.length > 0 && (
                <Section title={`Social / External Links (${socialProfiles.length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {socialProfiles.map((sp, i) => {
                            const platform = typeof sp === 'string' ? undefined : sp.platform;
                            const url      = typeof sp === 'string' ? sp : sp.url;
                            return (
                                <div key={i} className="flex items-center gap-2 text-sm">
                                    {platform && <Badge variant="info" size="sm">{platform}</Badge>}
                                    <span className="font-mono text-text-secondary break-all">{url}</span>
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── WHOIS ── */}
            {whoisMod && (
                <Section title="WHOIS Information" icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-2 text-sm">
                        {whoisMod.domain && (
                            <div className="flex gap-3">
                                <span className="text-text-tertiary w-32 flex-shrink-0">Domain</span>
                                <span className="font-mono text-text-primary">{whoisMod.domain}</span>
                            </div>
                        )}
                        {(whoisMod.registrar ?? whoisMod.registrarName) && (
                            <div className="flex gap-3">
                                <span className="text-text-tertiary w-32 flex-shrink-0">Registrar</span>
                                <span className="text-text-primary">{whoisMod.registrar ?? whoisMod.registrarName}</span>
                            </div>
                        )}
                        {(whoisMod.creationDate ?? whoisMod.creation_date) && (
                            <div className="flex gap-3">
                                <span className="text-text-tertiary w-32 flex-shrink-0">Created</span>
                                <span className="font-mono text-text-primary">{whoisMod.creationDate ?? whoisMod.creation_date}</span>
                            </div>
                        )}
                        {(whoisMod.expirationDate ?? whoisMod.expiration_date) && (
                            <div className="flex gap-3">
                                <span className="text-text-tertiary w-32 flex-shrink-0">Expires</span>
                                <span className="font-mono text-text-primary">{whoisMod.expirationDate ?? whoisMod.expiration_date}</span>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Attack Surface Summary ── */}
            {attackSurface && (
                <Section title="Attack Surface" icon={iconChart} defaultOpen={false}>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {attackSurface.entryPoints !== undefined && (
                            <div className="text-center p-3 bg-bg-secondary rounded-lg">
                                <div className="text-2xl font-bold text-text-primary">
                                    {Array.isArray(attackSurface.entryPoints) ? attackSurface.entryPoints.length : attackSurface.entryPoints}
                                </div>
                                <div className="text-xs text-text-tertiary mt-1">Entry Points</div>
                            </div>
                        )}
                        {attackSurface.services !== undefined && (
                            <div className="text-center p-3 bg-bg-secondary rounded-lg">
                                <div className="text-2xl font-bold text-text-primary">
                                    {Array.isArray(attackSurface.services) ? attackSurface.services.length : attackSurface.services}
                                </div>
                                <div className="text-xs text-text-tertiary mt-1">Services</div>
                            </div>
                        )}
                        {attackSurface.attackVectors !== undefined && (
                            <div className="text-center p-3 bg-bg-secondary rounded-lg">
                                <div className="text-2xl font-bold text-text-primary">
                                    {Array.isArray(attackSurface.attackVectors) ? attackSurface.attackVectors.length : attackSurface.attackVectors}
                                </div>
                                <div className="text-xs text-text-tertiary mt-1">Attack Vectors</div>
                            </div>
                        )}
                        {attackSurface.surfaceScore !== undefined && (
                            <div className="text-center p-3 bg-bg-secondary rounded-lg">
                                <div className={`text-2xl font-bold ${(attackSurface.surfaceScore ?? 0) >= 70 ? 'text-status-critical' : 'text-accent-green'}`}>
                                    {attackSurface.surfaceScore}
                                </div>
                                <div className="text-xs text-text-tertiary mt-1">Surface Score</div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Scan Stats ── */}
            {stats && (
                <Section title="Scan Phase Timings" icon={iconChart} defaultOpen={false}>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        {Object.entries(stats as Record<string, unknown>).map(([phase, val]) => (
                            <div key={phase} className="p-3 bg-bg-secondary rounded-lg">
                                <div className="text-xs text-text-tertiary mb-1">{phase}</div>
                                <div className="text-sm font-mono text-text-primary">{str(val)}</div>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── DNS Records ── */}
            {reconData.dns && (
                <Section title="DNS Records" icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-3">
                        {(reconData.dns.ip_addresses ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">IP Addresses</div>
                                <div className="flex flex-wrap gap-2">
                                    {(reconData.dns.ip_addresses as string[]).map((ip: string, i: number) => (
                                        <code key={i} className="text-sm font-mono bg-bg-secondary text-accent-green px-2 py-1 rounded">{ip}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.dns.nameservers ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">Nameservers</div>
                                <div className="flex flex-wrap gap-2">
                                    {(reconData.dns.nameservers as string[]).map((ns: string, i: number) => (
                                        <code key={i} className="text-sm font-mono bg-bg-secondary text-text-secondary px-2 py-1 rounded">{ns}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.dns.mx_records ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">MX Records</div>
                                <div className="flex flex-wrap gap-2">
                                    {(reconData.dns.mx_records as string[]).map((mx: string, i: number) => (
                                        <code key={i} className="text-sm font-mono bg-bg-secondary text-text-secondary px-2 py-1 rounded">{mx}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.dns.txt_records ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">TXT Records</div>
                                <div className="space-y-1 max-h-40 overflow-y-auto">
                                    {(reconData.dns.txt_records as string[]).map((txt: string, i: number) => (
                                        <code key={i} className="block text-xs font-mono bg-bg-secondary text-text-secondary px-2 py-1 rounded break-all">{txt}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Open Ports ── */}
            {reconData.ports && (reconData.ports.open_ports ?? []).length > 0 && (
                <Section title={`Open Ports (${(reconData.ports.open_ports as unknown[]).length})`} icon={iconChart} defaultOpen={false}>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-border-primary">
                                    <th className="text-left py-2 pr-4 text-text-tertiary font-medium">Port</th>
                                    <th className="text-left py-2 pr-4 text-text-tertiary font-medium">Protocol</th>
                                    <th className="text-left py-2 text-text-tertiary font-medium">Service</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(reconData.ports.open_ports as Array<{port?: number; protocol?: string; service?: string} | string>).map((p, i) => {
                                    if (typeof p === 'object' && p !== null) {
                                        return (
                                            <tr key={i} className="border-b border-border-primary/30">
                                                <td className="py-2 pr-4 font-mono text-accent-green font-semibold">{p.port ?? '—'}</td>
                                                <td className="py-2 pr-4 text-text-secondary">{p.protocol ?? 'tcp'}</td>
                                                <td className="py-2 text-text-secondary">{p.service ?? '—'}</td>
                                            </tr>
                                        );
                                    }
                                    return (
                                        <tr key={i} className="border-b border-border-primary/30">
                                            <td className="py-2 pr-4 font-mono text-accent-green font-semibold" colSpan={3}>{str(p)}</td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </Section>
            )}

            {/* ── Active Subdomains (from subdomain_enum) ── */}
            {reconData.subdomains && (reconData.subdomains.subdomains ?? []).length > 0 && (
                <Section title={`Active Subdomains — Enumeration (${(reconData.subdomains.subdomains as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                        {(reconData.subdomains.subdomains as unknown[]).map((sub: any, i: number) => (
                            <code key={i} className="text-sm text-accent-green font-mono bg-bg-secondary px-3 py-1.5 rounded">{typeof sub === 'string' ? sub : sub?.name ? `${sub.name}${sub.ip ? ` (${sub.ip})` : ''}` : str(sub)}</code>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── CT Log Subdomains ── */}
            {reconData.ct_logs && (reconData.ct_logs.subdomains ?? []).length > 0 && (
                <Section title={`Certificate Transparency Subdomains (${(reconData.ct_logs.subdomains as unknown[]).length})`} icon={iconLock} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                        {(reconData.ct_logs.subdomains as unknown[]).map((sub: any, i: number) => (
                            <code key={i} className="text-sm text-text-secondary font-mono bg-bg-secondary px-3 py-1.5 rounded">{typeof sub === 'string' ? sub : sub?.name ? `${sub.name}${sub.ip ? ` (${sub.ip})` : ''}` : str(sub)}</code>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Brute-forced Subdomains ── */}
            {reconData.subdomain_brute && (reconData.subdomain_brute.new_subdomains ?? reconData.subdomain_brute.subdomains ?? []).length > 0 && (
                <Section title={`Brute-forced Subdomains (${((reconData.subdomain_brute.new_subdomains ?? reconData.subdomain_brute.subdomains) as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                        {((reconData.subdomain_brute.new_subdomains ?? reconData.subdomain_brute.subdomains) as unknown[]).map((sub: any, i: number) => (
                            <code key={i} className="text-sm text-text-secondary font-mono bg-bg-secondary px-3 py-1.5 rounded">{typeof sub === 'string' ? sub : sub?.name ? `${sub.name}${sub.ip ? ` (${sub.ip})` : ''}` : str(sub)}</code>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Subdomain Takeover ── */}
            {reconData.subdomain_takeover && (reconData.subdomain_takeover.vulnerable_subdomains ?? reconData.subdomain_takeover.findings ?? []).length > 0 && (
                <Section title="Subdomain Takeover Candidates" icon={iconShield} defaultOpen={true}>
                    <div className="space-y-2">
                        {((reconData.subdomain_takeover.vulnerable_subdomains ?? reconData.subdomain_takeover.findings) as Array<{subdomain?: string; cname?: string; service?: string} | string>).map((item, i) => {
                            if (typeof item === 'string') return (
                                <div key={i} className="flex items-center gap-2">
                                    <Badge variant="critical" size="sm">Vulnerable</Badge>
                                    <code className="text-sm font-mono text-status-critical">{item}</code>
                                </div>
                            );
                            return (
                                <div key={i} className="flex items-center gap-3 flex-wrap text-sm">
                                    <Badge variant="critical" size="sm">Vulnerable</Badge>
                                    <code className="font-mono text-status-critical">{item.subdomain ?? '—'}</code>
                                    {item.cname && <span className="text-text-tertiary">→ {item.cname}</span>}
                                    {item.service && <Badge variant="high" size="sm">{item.service}</Badge>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── ASN / CIDR ── */}
            {reconData.asn && (
                <Section title="ASN / CIDR Enumeration" icon={iconChart} defaultOpen={false}>
                    <div className="space-y-3">
                        {(reconData.asn.asns ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">ASN Numbers</div>
                                <div className="flex flex-wrap gap-2">
                                    {(reconData.asn.asns as Array<{asn?: string; org?: string} | string>).map((a, i) => (
                                        <span key={i} className="px-2 py-1 bg-bg-secondary text-text-primary rounded text-sm font-mono">
                                            {typeof a === 'string' ? a : `${a.asn ?? ''}${a.org ? ` (${a.org})` : ''}`}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.asn.cidrs ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">CIDR Blocks</div>
                                <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                                    {(reconData.asn.cidrs as string[]).map((cidr, i) => (
                                        <code key={i} className="text-xs font-mono bg-bg-secondary text-accent-green px-2 py-1 rounded">{cidr}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Wildcard DNS ── */}
            {reconData.wildcard && (
                <Section title="Wildcard DNS Detection" icon={iconGlobe} defaultOpen={false}>
                    <div className="flex items-center gap-4 flex-wrap">
                        <Badge variant={reconData.wildcard.wildcard_detected ? 'critical' : 'low'}>
                            {reconData.wildcard.wildcard_detected ? 'Wildcard Detected' : 'No Wildcard'}
                        </Badge>
                        {reconData.wildcard.wildcard_type && (
                            <span className="text-sm text-text-secondary">Type: <span className="font-mono">{str(reconData.wildcard.wildcard_type)}</span></span>
                        )}
                        {(reconData.wildcard.wildcard_ips ?? []).length > 0 && (
                            <span className="text-sm text-text-secondary">IPs: {(reconData.wildcard.wildcard_ips as string[]).join(', ')}</span>
                        )}
                    </div>
                </Section>
            )}

            {/* ── DNS Zone Enum ── */}
            {reconData.dns_zone && (reconData.dns_zone.srv_records ?? []).length > 0 && (
                <Section title={`DNS Zone Enumeration (${(reconData.dns_zone.srv_records as unknown[]).length} SRV records)`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {(reconData.dns_zone.srv_records as Array<{name?: string; target?: string; port?: number} | string>).map((r, i) => (
                            <div key={i} className="text-sm font-mono bg-bg-secondary px-3 py-1.5 rounded text-text-secondary">
                                {typeof r === 'string' ? r : `${r.name ?? ''} → ${r.target ?? ''}${r.port ? `:${r.port}` : ''}`}
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Harvested URLs ── */}
            {reconData.urls && (reconData.urls.urls ?? reconData.urls.internal_urls ?? []).length > 0 && (() => {
                const urlList = (reconData.urls.urls ?? reconData.urls.internal_urls) as string[];
                return (
                    <Section title={`Harvested URLs (${urlList.length})`} icon={iconGlobe} defaultOpen={false}>
                        <div className="space-y-1 max-h-64 overflow-y-auto">
                            {urlList.slice(0, 200).map((u, i) => (
                                <code key={i} className="block text-xs font-mono text-accent-green bg-bg-secondary px-2 py-1 rounded break-all">{u}</code>
                            ))}
                            {urlList.length > 200 && <div className="text-xs text-text-tertiary pt-1">… and {urlList.length - 200} more</div>}
                        </div>
                    </Section>
                );
            })()}

            {/* ── URL Intelligence (Wayback / CommonCrawl) ── */}
            {reconData.url_intelligence && (reconData.url_intelligence.urls ?? []).length > 0 && (
                <Section title={`Historical URLs — Wayback/CommonCrawl (${(reconData.url_intelligence.urls as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                        {(reconData.url_intelligence.urls as string[]).slice(0, 100).map((u, i) => (
                            <code key={i} className="block text-xs font-mono text-text-secondary bg-bg-secondary px-2 py-1 rounded break-all">{u}</code>
                        ))}
                        {(reconData.url_intelligence.urls as string[]).length > 100 && (
                            <div className="text-xs text-text-tertiary pt-1">… and {(reconData.url_intelligence.urls as string[]).length - 100} more</div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── HTTP Probe (live hosts) ── */}
            {reconData.http_probe && (reconData.http_probe.live_hosts ?? []).length > 0 && (
                <Section title={`Live Hosts — HTTP Probe (${(reconData.http_probe.live_hosts as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                        {(reconData.http_probe.live_hosts as Array<{url?: string; status?: number; title?: string} | string>).map((h, i) => {
                            if (typeof h === 'string') return <code key={i} className="text-sm font-mono text-accent-green bg-bg-secondary px-3 py-1.5 rounded">{h}</code>;
                            return (
                                <div key={i} className="bg-bg-secondary px-3 py-2 rounded text-sm">
                                    <div className="font-mono text-accent-green">{h.url ?? '—'}</div>
                                    {(h.status || h.title) && (
                                        <div className="text-xs text-text-tertiary mt-0.5">
                                            {h.status && <span className="mr-2">HTTP {h.status}</span>}
                                            {h.title && <span>{h.title}</span>}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── Screenshot Recon ── */}
            {reconData.screenshot && (reconData.screenshot.pages ?? []).length > 0 && (
                <Section title={`Screenshot Recon (${(reconData.screenshot.pages as unknown[]).length} pages)`} icon={iconCode} defaultOpen={false}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-64 overflow-y-auto">
                        {(reconData.screenshot.pages as Array<{url?: string; classification?: string; risk?: string; screenshot_path?: string}>).map((p, i) => (
                            <div key={i} className="bg-bg-secondary rounded px-3 py-2 text-sm">
                                <div className="font-mono text-accent-green break-all">{p.url ?? '—'}</div>
                                <div className="flex gap-2 mt-1">
                                    {p.classification && <Badge variant="info" size="sm">{p.classification}</Badge>}
                                    {p.risk && <Badge variant={p.risk === 'high' ? 'high' : p.risk === 'medium' ? 'medium' : 'low'} size="sm">Risk: {p.risk}</Badge>}
                                </div>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── JS Analysis (getJS / linkfinder) ── */}
            {reconData.js_analysis && (
                <Section title="JavaScript Analysis" icon={iconCode} defaultOpen={false}>
                    <div className="space-y-3">
                        {(reconData.js_analysis.scripts ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">JS Files ({(reconData.js_analysis.scripts as unknown[]).length})</div>
                                <div className="space-y-1 max-h-32 overflow-y-auto">
                                    {(reconData.js_analysis.scripts as string[]).slice(0, 50).map((s, i) => (
                                        <code key={i} className="block text-xs font-mono text-accent-green bg-bg-secondary px-2 py-1 rounded break-all">{s}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.js_analysis.endpoints ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">Endpoints Found ({(reconData.js_analysis.endpoints as unknown[]).length})</div>
                                <div className="space-y-1 max-h-32 overflow-y-auto">
                                    {(reconData.js_analysis.endpoints as string[]).slice(0, 50).map((e, i) => (
                                        <code key={i} className="block text-xs font-mono text-text-secondary bg-bg-secondary px-2 py-1 rounded break-all">{e}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                        {(reconData.js_analysis.secrets ?? []).length > 0 && (
                            <div>
                                <div className="text-xs font-semibold text-status-critical uppercase mb-2">⚠ Secrets Found ({(reconData.js_analysis.secrets as unknown[]).length})</div>
                                <div className="space-y-1.5">
                                    {(reconData.js_analysis.secrets as Array<{type?: string; value?: string; file?: string} | string>).map((s, i) => (
                                        <div key={i} className="bg-status-critical/5 border border-status-critical/20 rounded px-3 py-1.5 text-sm">
                                            {typeof s === 'string' ? <code className="font-mono text-status-critical break-all">{s}</code> : (
                                                <div>
                                                    {s.type && <Badge variant="critical" size="sm">{s.type}</Badge>}
                                                    <code className="ml-2 font-mono text-status-critical break-all">{s.value ?? str(s)}</code>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Favicon Hash ── */}
            {reconData.favicon && (reconData.favicon.favicon_hash || reconData.favicon.technology) && (
                <Section title="Favicon Hash Fingerprinting" icon={iconCode} defaultOpen={false}>
                    <div className="flex items-center gap-4 flex-wrap text-sm">
                        {reconData.favicon.favicon_hash && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">MMH3 Hash</div>
                                <code className="font-mono text-accent-green">{str(reconData.favicon.favicon_hash)}</code>
                            </div>
                        )}
                        {reconData.favicon.technology && (
                            <div>
                                <div className="text-xs text-text-tertiary mb-1">Matched Technology</div>
                                <Badge variant="info">{str((reconData.favicon.technology as Record<string, unknown>)?.name ?? reconData.favicon.technology)}</Badge>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Secrets (Recon secret scanner via trufflehog) ── */}
            {reconData.secrets && (reconData.secrets.findings ?? []).length > 0 && (
                <Section title={`Secrets Found — Recon (${(reconData.secrets.findings as unknown[]).length})`} icon={iconLock} defaultOpen={true}>
                    <div className="space-y-2">
                        {(reconData.secrets.findings as Array<{type?: string; value?: string; url?: string; confidence?: string} | string>).map((f, i) => {
                            if (typeof f === 'string') return (
                                <div key={i} className="bg-status-critical/5 border border-status-critical/20 rounded px-3 py-2 text-sm">
                                    <code className="font-mono text-status-critical break-all">{f}</code>
                                </div>
                            );
                            return (
                                <div key={i} className="bg-status-critical/5 border border-status-critical/20 rounded px-3 py-2 text-sm space-y-1">
                                    <div className="flex items-center gap-2">
                                        {f.type && <Badge variant="critical" size="sm">{f.type}</Badge>}
                                        {f.confidence && <Badge variant="high" size="sm">{f.confidence}</Badge>}
                                    </div>
                                    {f.value && <code className="block font-mono text-status-critical break-all">{f.value}</code>}
                                    {f.url && <div className="text-xs text-text-tertiary">Source: {f.url}</div>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── Cloud Enum (cloud_enum / s3scanner) ── */}
            {reconData.cloud_enum && (
                <Section title="Cloud Bucket Enumeration" icon={iconCloud} defaultOpen={false}>
                    <div className="space-y-3">
                        {(reconData.cloud_enum.buckets ?? reconData.cloud_enum.findings ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">Buckets Found</div>
                                <div className="space-y-1.5">
                                    {((reconData.cloud_enum.buckets ?? reconData.cloud_enum.findings) as Array<{name?: string; provider?: string; public?: boolean; url?: string} | string>).map((b, i) => {
                                        if (typeof b === 'string') return <code key={i} className="block text-sm font-mono bg-bg-secondary text-accent-green px-2 py-1 rounded">{b}</code>;
                                        return (
                                            <div key={i} className="flex items-center gap-2 flex-wrap text-sm">
                                                <code className="font-mono text-accent-green">{b.name ?? b.url ?? str(b)}</code>
                                                {b.provider && <Badge variant="info" size="sm">{b.provider}</Badge>}
                                                {b.public !== undefined && <Badge variant={b.public ? 'critical' : 'low'} size="sm">{b.public ? 'PUBLIC' : 'Private'}</Badge>}
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Cloud Recon (extended) ── */}
            {reconData.cloud_recon && (reconData.cloud_recon.findings ?? reconData.cloud_recon.results ?? []).length > 0 && (
                <Section title="Extended Cloud Recon" icon={iconCloud} defaultOpen={false}>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                        {((reconData.cloud_recon.findings ?? reconData.cloud_recon.results) as unknown[]).map((item, i) => (
                            <div key={i} className="text-sm bg-bg-secondary px-3 py-1.5 rounded font-mono text-text-secondary break-all">{str(item)}</div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Content Discovery (gobuster) ── */}
            {reconData.content_discovery && (reconData.content_discovery.paths ?? reconData.content_discovery.findings ?? []).length > 0 && (() => {
                const paths = (reconData.content_discovery.paths ?? reconData.content_discovery.findings) as Array<{path?: string; status?: number; size?: number} | string>;
                return (
                    <Section title={`Content Discovery (${paths.length} paths found)`} icon={iconCode} defaultOpen={false}>
                        <div className="overflow-x-auto max-h-64">
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="border-b border-border-primary">
                                        <th className="text-left py-2 pr-4 text-text-tertiary font-medium">Path</th>
                                        <th className="text-center py-2 pr-4 text-text-tertiary font-medium">Status</th>
                                        <th className="text-right py-2 text-text-tertiary font-medium">Size</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {paths.slice(0, 100).map((p, i) => (
                                        <tr key={i} className="border-b border-border-primary/30">
                                            <td className="py-1.5 pr-4 font-mono text-accent-green text-xs">{typeof p === 'string' ? p : (p.path ?? str(p))}</td>
                                            <td className="py-1.5 pr-4 text-center">
                                                {typeof p === 'object' && p.status ? (
                                                    <Badge variant={p.status < 300 ? 'low' : p.status < 400 ? 'medium' : p.status < 500 ? 'high' : 'info'} size="sm">{p.status}</Badge>
                                                ) : '—'}
                                            </td>
                                            <td className="py-1.5 text-right text-text-tertiary text-xs">{typeof p === 'object' && p.size ? `${p.size}b` : '—'}</td>
                                        </tr>
                                    ))}
                                    {paths.length > 100 && (
                                        <tr><td colSpan={3} className="py-2 text-xs text-text-tertiary">… and {paths.length - 100} more paths</td></tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </Section>
                );
            })()}

            {/* ── Parameter Discovery ── */}
            {reconData.param_discovery && (reconData.param_discovery.params ?? reconData.param_discovery.parameters ?? []).length > 0 && (
                <Section title={`Parameter Discovery (${((reconData.param_discovery.params ?? reconData.param_discovery.parameters) as unknown[]).length})`} icon={iconCode} defaultOpen={false}>
                    <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto">
                        {((reconData.param_discovery.params ?? reconData.param_discovery.parameters) as Array<{name?: string; url?: string} | string>).map((p, i) => (
                            <code key={i} className="text-xs font-mono bg-bg-secondary text-accent-green px-2 py-1 rounded">
                                {typeof p === 'string' ? p : p.name ?? str(p)}
                            </code>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── API Discovery ── */}
            {reconData.api_discovery && (reconData.api_discovery.endpoints ?? []).length > 0 && (
                <Section title={`API Endpoints Discovered (${(reconData.api_discovery.endpoints as unknown[]).length})`} icon={iconCode} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {(reconData.api_discovery.endpoints as Array<{method?: string; path?: string; auth?: boolean} | string>).map((ep, i) => (
                            <div key={i} className="flex items-center gap-2 text-sm bg-bg-secondary px-3 py-1.5 rounded">
                                {typeof ep === 'object' && ep.method && (
                                    <Badge variant={ep.method === 'GET' ? 'low' : ep.method === 'POST' ? 'medium' : 'high'} size="sm">{ep.method}</Badge>
                                )}
                                <code className="font-mono text-accent-green">{typeof ep === 'string' ? ep : (ep.path ?? str(ep))}</code>
                                {typeof ep === 'object' && ep.auth !== undefined && (
                                    <Badge variant={ep.auth ? 'low' : 'high'} size="sm">{ep.auth ? '🔒 Auth' : '🔓 Open'}</Badge>
                                )}
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Network Map ── */}
            {reconData.network && (reconData.network.nodes ?? reconData.network.hosts ?? []).length > 0 && (
                <Section title="Network Topology" icon={iconChart} defaultOpen={false}>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        {['nodes', 'hosts', 'edges', 'services', 'subnets'].map((key) => {
                            const val = reconData.network[key];
                            if (!val) return null;
                            const count = Array.isArray(val) ? val.length : val;
                            return (
                                <div key={key} className="p-3 bg-bg-secondary rounded-lg text-center">
                                    <div className="text-xl font-bold text-text-primary">{count}</div>
                                    <div className="text-xs text-text-tertiary mt-1 capitalize">{key}</div>
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── Reverse DNS ── */}
            {reconData.reverse_dns && (reconData.reverse_dns.results ?? []).length > 0 && (
                <Section title={`Reverse DNS (${(reconData.reverse_dns.results as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                        {(reconData.reverse_dns.results as Array<{ip?: string; hostname?: string} | string>).map((r, i) => (
                            <div key={i} className="flex items-center gap-3 text-sm bg-bg-secondary px-3 py-1.5 rounded">
                                {typeof r === 'object' ? (
                                    <>
                                        <code className="font-mono text-text-tertiary">{r.ip ?? '—'}</code>
                                        <span className="text-text-tertiary">→</span>
                                        <code className="font-mono text-accent-green">{r.hostname ?? '—'}</code>
                                    </>
                                ) : <code className="font-mono text-text-secondary">{r}</code>}
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Google Dorking ── */}
            {reconData.dorking && (reconData.dorking.results ?? reconData.dorking.findings ?? []).length > 0 && (
                <Section title={`Google Dorking Results (${((reconData.dorking.results ?? reconData.dorking.findings) as unknown[]).length})`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {((reconData.dorking.results ?? reconData.dorking.findings) as Array<{query?: string; url?: string; type?: string} | string>).map((r, i) => {
                            if (typeof r === 'string') return <code key={i} className="block text-sm font-mono text-text-secondary bg-bg-secondary px-2 py-1 rounded break-all">{r}</code>;
                            return (
                                <div key={i} className="bg-bg-secondary px-3 py-2 rounded text-sm">
                                    {r.type && <Badge variant="info" size="sm">{r.type}</Badge>}
                                    {r.query && <code className="ml-2 text-xs font-mono text-text-tertiary">{r.query}</code>}
                                    {r.url && <div className="font-mono text-accent-green text-xs mt-1 break-all">{r.url}</div>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── AI Endpoints ── */}
            {reconData.ai && reconData.ai.detected && (reconData.ai.endpoints ?? []).length > 0 && (
                <Section title={`AI Endpoints Detected (${(reconData.ai.endpoints as unknown[]).length})`} icon={iconChart} defaultOpen={false}>
                    <div className="space-y-1.5">
                        {(reconData.ai.endpoints as Array<{url?: string; type?: string; confidence?: string} | string>).map((ep, i) => {
                            if (typeof ep === 'string') return <code key={i} className="block text-sm font-mono text-accent-green bg-bg-secondary px-2 py-1 rounded">{ep}</code>;
                            return (
                                <div key={i} className="flex items-center gap-2 text-sm">
                                    <code className="font-mono text-accent-green">{ep.url ?? str(ep)}</code>
                                    {ep.type && <Badge variant="info" size="sm">{ep.type}</Badge>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── OSINT: Shodan ── */}
            {reconData.shodan && (reconData.shodan.ports ?? reconData.shodan.services ?? []).length > 0 && (
                <Section title="OSINT — Shodan Intelligence" icon={iconChart} defaultOpen={false}>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                        {reconData.shodan.country && <div className="p-3 bg-bg-secondary rounded text-center"><div className="text-sm font-semibold text-text-primary">{str(reconData.shodan.country)}</div><div className="text-xs text-text-tertiary mt-1">Country</div></div>}
                        {reconData.shodan.org && <div className="p-3 bg-bg-secondary rounded text-center"><div className="text-sm font-semibold text-text-primary">{str(reconData.shodan.org)}</div><div className="text-xs text-text-tertiary mt-1">Org</div></div>}
                        {reconData.shodan.isp && <div className="p-3 bg-bg-secondary rounded text-center"><div className="text-sm font-semibold text-text-primary">{str(reconData.shodan.isp)}</div><div className="text-xs text-text-tertiary mt-1">ISP</div></div>}
                        {(reconData.shodan.ports ?? []).length > 0 && <div className="p-3 bg-bg-secondary rounded text-center"><div className="text-xl font-bold text-accent-green">{(reconData.shodan.ports as unknown[]).length}</div><div className="text-xs text-text-tertiary mt-1">Ports</div></div>}
                    </div>
                    {(reconData.shodan.vulns ?? []).length > 0 && (
                        <div>
                            <div className="text-xs text-text-tertiary uppercase mb-2">CVEs from Shodan</div>
                            <div className="flex flex-wrap gap-2">
                                {(reconData.shodan.vulns as string[]).map((cve, i) => <Badge key={i} variant="critical" size="sm">{cve}</Badge>)}
                            </div>
                        </div>
                    )}
                </Section>
            )}

            {/* ── OSINT: Censys ── */}
            {reconData.censys && (reconData.censys.services ?? reconData.censys.certificates ?? []).length > 0 && (
                <Section title="OSINT — Censys Intelligence" icon={iconChart} defaultOpen={false}>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                        {((reconData.censys.services ?? reconData.censys.certificates) as unknown[]).map((s, i) => (
                            <div key={i} className="text-sm bg-bg-secondary px-3 py-1.5 rounded font-mono text-text-secondary">{str(s)}</div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── OSINT: VirusTotal ── */}
            {reconData.vt_intel && (
                <Section title="OSINT — VirusTotal Intelligence" icon={iconShield} defaultOpen={false}>
                    <div className="flex items-center gap-4 flex-wrap text-sm">
                        {reconData.vt_intel.malicious !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className={`text-2xl font-bold ${(reconData.vt_intel.malicious as number) > 0 ? 'text-status-critical' : 'text-accent-green'}`}>{str(reconData.vt_intel.malicious)}</div>
                                <div className="text-xs text-text-tertiary mt-1">Malicious Detections</div>
                            </div>
                        )}
                        {reconData.vt_intel.suspicious !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className={`text-2xl font-bold ${(reconData.vt_intel.suspicious as number) > 0 ? 'text-status-high' : 'text-text-secondary'}`}>{str(reconData.vt_intel.suspicious)}</div>
                                <div className="text-xs text-text-tertiary mt-1">Suspicious</div>
                            </div>
                        )}
                        {reconData.vt_intel.reputation !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className="text-2xl font-bold text-text-primary">{str(reconData.vt_intel.reputation)}</div>
                                <div className="text-xs text-text-tertiary mt-1">Reputation Score</div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── OSINT: Wayback Intelligence ── */}
            {reconData.wayback && (reconData.wayback.snapshots ?? reconData.wayback.urls ?? []).length > 0 && (
                <Section title={`OSINT — Wayback Machine (${((reconData.wayback.snapshots ?? reconData.wayback.urls) as unknown[]).length} snapshots)`} icon={iconGlobe} defaultOpen={false}>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                        {((reconData.wayback.snapshots ?? reconData.wayback.urls) as Array<{url?: string; timestamp?: string} | string>).slice(0, 50).map((s, i) => (
                            <div key={i} className="text-xs bg-bg-secondary px-3 py-1.5 rounded font-mono text-text-secondary flex items-center gap-2">
                                {typeof s === 'object' && s.timestamp && <span className="text-text-tertiary flex-shrink-0">{s.timestamp}</span>}
                                <span className="break-all">{typeof s === 'string' ? s : (s.url ?? str(s))}</span>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── OSINT: GitHub Intelligence ── */}
            {reconData.github_intel && (reconData.github_intel.findings ?? reconData.github_intel.repos ?? []).length > 0 && (
                <Section title={`OSINT — GitHub Intelligence (${((reconData.github_intel.findings ?? reconData.github_intel.repos) as unknown[]).length})`} icon={iconCode} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {((reconData.github_intel.findings ?? reconData.github_intel.repos) as Array<{repo?: string; type?: string; match?: string} | string>).map((f, i) => {
                            if (typeof f === 'string') return <div key={i} className="text-sm bg-bg-secondary px-3 py-1.5 rounded font-mono text-text-secondary">{f}</div>;
                            return (
                                <div key={i} className="bg-bg-secondary px-3 py-2 rounded text-sm">
                                    {f.type && <Badge variant={f.type === 'secret' ? 'critical' : 'info'} size="sm">{f.type}</Badge>}
                                    {f.repo && <span className="ml-2 font-mono text-accent-green">{f.repo}</span>}
                                    {f.match && <div className="text-xs text-text-tertiary mt-1 break-all">{f.match}</div>}
                                </div>
                            );
                        })}
                    </div>
                </Section>
            )}

            {/* ── Threat Intelligence ── */}
            {reconData.threat_intel && (
                <Section title="Threat Intelligence" icon={iconShield} defaultOpen={false}>
                    <div className="space-y-3">
                        {reconData.threat_intel.risk_level && (
                            <div className="flex items-center gap-3">
                                <span className="text-sm text-text-tertiary">Risk Level:</span>
                                <Badge variant={reconData.threat_intel.risk_level === 'high' ? 'high' : reconData.threat_intel.risk_level === 'medium' ? 'medium' : 'low'}>
                                    {str(reconData.threat_intel.risk_level).toUpperCase()}
                                </Badge>
                            </div>
                        )}
                        {(reconData.threat_intel.indicators ?? []).length > 0 && (
                            <div>
                                <div className="text-xs text-text-tertiary uppercase mb-2">Threat Indicators</div>
                                <div className="space-y-1 max-h-32 overflow-y-auto">
                                    {(reconData.threat_intel.indicators as Array<{type?: string; value?: string; source?: string} | string>).map((ind, i) => (
                                        <div key={i} className="flex items-center gap-2 text-sm">
                                            {typeof ind === 'object' && ind.type && <Badge variant="high" size="sm">{ind.type}</Badge>}
                                            <span className="font-mono text-text-secondary">{typeof ind === 'string' ? ind : (ind.value ?? str(ind))}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </Section>
            )}

            {/* ── Vuln Correlation ── */}
            {reconData.vuln_correlation && (reconData.vuln_correlation.correlated ?? []).length > 0 && (
                <Section title={`Vulnerability Correlations (${(reconData.vuln_correlation.correlated as unknown[]).length})`} icon={iconShield} defaultOpen={false}>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {(reconData.vuln_correlation.correlated as Array<{category?: string; count?: number; description?: string} | string>).map((c, i) => (
                            <div key={i} className="bg-bg-secondary px-3 py-2 rounded text-sm flex items-center gap-2">
                                {typeof c === 'object' ? (
                                    <>
                                        {c.category && <Badge variant="high" size="sm">{c.category}</Badge>}
                                        {c.count !== undefined && <span className="font-bold text-text-primary">{c.count}×</span>}
                                        {c.description && <span className="text-text-secondary">{c.description}</span>}
                                    </>
                                ) : <span className="text-text-secondary">{c}</span>}
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* ── Scope Analysis ── */}
            {reconData.scope && (
                <Section title="Scope Analysis" icon={iconChart} defaultOpen={false}>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        {reconData.scope.in_scope_count !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className="text-xl font-bold text-accent-green">{str(reconData.scope.in_scope_count)}</div>
                                <div className="text-xs text-text-tertiary mt-1">In Scope</div>
                            </div>
                        )}
                        {reconData.scope.out_of_scope_count !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className="text-xl font-bold text-text-secondary">{str(reconData.scope.out_of_scope_count)}</div>
                                <div className="text-xs text-text-tertiary mt-1">Out of Scope</div>
                            </div>
                        )}
                        {reconData.scope.coverage !== undefined && (
                            <div className="p-3 bg-bg-secondary rounded text-center">
                                <div className="text-xl font-bold text-text-primary">{str(reconData.scope.coverage)}%</div>
                                <div className="text-xs text-text-tertiary mt-1">Coverage</div>
                            </div>
                        )}
                    </div>
                </Section>
            )}
        </div>
    );
}
