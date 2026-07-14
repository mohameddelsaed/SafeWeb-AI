import { useState, useEffect, useRef } from 'react';

interface ScanTimerResult {
    elapsed: string;        // "MM:SS" or "HH:MM:SS"
    remaining: string;      // "~MM:SS" or "--:--" if unknown
    elapsedSeconds: number;
}

/**
 * Real-time elapsed/remaining timer for active scans.
 *
 * - Elapsed ticks every second from `startedAt`.
 * - Remaining counts down from `serverEstimatedRemaining` and re-syncs
 *   whenever a fresh SSE `progress` event provides a new estimate.
 */
export function useScanTimer(
    startedAt: string | undefined | null,
    serverEstimatedRemaining: number | undefined | null,
    isActive: boolean,
): ScanTimerResult {
    const [elapsedSeconds, setElapsedSeconds] = useState(0);
    const [remainingSeconds, setRemainingSeconds] = useState<number | null>(null);

    // Track the last server-provided estimate so we can re-sync on updates
    const lastServerEstimate = useRef<number | null>(null);
    const lastSyncTime = useRef<number>(Date.now());

    // Re-sync remaining from server whenever the estimate updates
    useEffect(() => {
        if (serverEstimatedRemaining != null && serverEstimatedRemaining > 0) {
            setRemainingSeconds(serverEstimatedRemaining);
            lastServerEstimate.current = serverEstimatedRemaining;
            lastSyncTime.current = Date.now();
        }
    }, [serverEstimatedRemaining]);

    // Tick every second
    useEffect(() => {
        if (!isActive || !startedAt) return;

        const startMs = new Date(startedAt).getTime();

        const tick = () => {
            const nowMs = Date.now();
            const elapsed = Math.max(0, Math.floor((nowMs - startMs) / 1000));
            setElapsedSeconds(elapsed);

            // Count remaining down locally between server syncs
            setRemainingSeconds((prev) => {
                if (prev == null) return null;
                const secondsSinceSync = Math.floor((nowMs - lastSyncTime.current) / 1000);
                const base = lastServerEstimate.current ?? prev;
                const updated = base - secondsSinceSync;
                return Math.max(0, updated);
            });
        };

        tick(); // immediate
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, [isActive, startedAt]);

    const fmt = (totalSecs: number): string => {
        const h = Math.floor(totalSecs / 3600);
        const m = Math.floor((totalSecs % 3600) / 60);
        const s = totalSecs % 60;
        const mm = String(m).padStart(2, '0');
        const ss = String(s).padStart(2, '0');
        return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
    };

    return {
        elapsed: fmt(elapsedSeconds),
        remaining: remainingSeconds != null && remainingSeconds > 0
            ? `~${fmt(remainingSeconds)}`
            : '--:--',
        elapsedSeconds,
    };
}
