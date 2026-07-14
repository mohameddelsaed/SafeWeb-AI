import { useEffect, useRef } from 'react';

export interface SSEProgressData {
    percent: number;
    phase: string;
    // Enhanced live fields
    currentTool?: string;
    startedAt?: string;
    elapsedSeconds?: number;
    estimatedRemainingSeconds?: number;
    findingCount?: number;
    status?: string;
    // Crawler / request counters
    pagesCrawled?: number;
    totalRequests?: number;
    // Incremental-data version from backend
    dataVersion?: number;
}

export interface SSEFindingData {
    totalFindings: number;
    newCount: number;
    phase: string;
    summary: Record<string, number>;
}

export interface SSEAgentActivityData {
    flowStatus: string;
    costMeterUsd: number;
    engagementLog: { step?: string; finding?: string; status?: string; target?: string; reproof?: string }[];
    taskGraph: Record<string, unknown>;
}

export interface SSECallbacks {
    onProgress?: (data: SSEProgressData) => void;
    onPhaseChange?: (data: { phase: string }) => void;
    onFinding?: (data: SSEFindingData) => void;
    onAgentActivity?: (data: SSEAgentActivityData) => void;
    onCompleted?: () => void;
    /** Fired when the backend increments data_version (recon_data / tester_results updated) */
    onDataUpdate?: (data: { dataVersion: number }) => void;
    onError?: () => void;
}

/**
 * Subscribes to a server-sent events stream for real-time scan updates.
 * Automatically cleans up the EventSource on unmount or when `url` changes.
 * Pass `null` as `url` to disable (e.g. when the scan is already finished).
 */
export function useSSE(url: string | null, callbacks: SSECallbacks): void {
    const cbRef = useRef(callbacks);
    cbRef.current = callbacks; // always up-to-date without re-subscribing

    useEffect(() => {
        if (!url) return;

        const es = new EventSource(url);

        const parse = (raw: string): Record<string, unknown> => {
            try { return JSON.parse(raw); } catch { return {}; }
        };

        es.addEventListener('progress', (e: MessageEvent) => {
            const d = parse(e.data);
            cbRef.current.onProgress?.({
                percent: (d.progress as number) ?? 0,
                phase: (d.currentPhase as string) ?? '',
                currentTool: d.currentTool as string | undefined,
                startedAt: d.startedAt as string | undefined,
                elapsedSeconds: d.elapsedSeconds as number | undefined,
                estimatedRemainingSeconds: d.estimatedRemainingSeconds as number | undefined,
                findingCount: d.findingCount as number | undefined,
                status: d.status as string | undefined,
                pagesCrawled: d.pagesCrawled as number | undefined,
                totalRequests: d.totalRequests as number | undefined,
                dataVersion: d.dataVersion as number | undefined,
            });
        });

        es.addEventListener('phase_change', (e: MessageEvent) => {
            cbRef.current.onPhaseChange?.(parse(e.data) as { phase: string });
        });

        es.addEventListener('finding', (e: MessageEvent) => {
            cbRef.current.onFinding?.(parse(e.data) as unknown as SSEFindingData);
        });

        es.addEventListener('data_update', (e: MessageEvent) => {
            cbRef.current.onDataUpdate?.(parse(e.data) as { dataVersion: number });
        });

        es.addEventListener('agent_activity', (e: MessageEvent) => {
            cbRef.current.onAgentActivity?.(parse(e.data) as unknown as SSEAgentActivityData);
        });

        es.addEventListener('completed', () => {
            cbRef.current.onCompleted?.();
            es.close();
        });

        es.addEventListener('error', () => {
            cbRef.current.onError?.();
            es.close();
        });

        es.onerror = () => {
            cbRef.current.onError?.();
            es.close();
        };

        return () => {
            es.close();
        };
    }, [url]);
}
