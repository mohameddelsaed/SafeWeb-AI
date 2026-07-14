import { useEffect, useRef, useState, useCallback } from 'react';
import { GLITCH, prefersReducedMotion } from '@utils/animationConfig';

interface GlitchTextProps {
    children: string;
    as?: 'h1' | 'h2' | 'h3' | 'h4' | 'span' | 'div';
    className?: string;
    /** Auto-trigger glitch. Set 0 to disable. Uses config defaults for interval range. */
    interval?: number;
}

export default function GlitchText({
    children,
    as: Tag = 'span',
    className = '',
    interval = GLITCH.intervalMin,
}: GlitchTextProps) {
    const [isActive, setIsActive] = useState(false);
    const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const burstRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const reduced = prefersReducedMotion();

    const triggerGlitch = useCallback(() => {
        if (reduced) return;
        setIsActive(true);
        if (burstRef.current) clearTimeout(burstRef.current);
        burstRef.current = setTimeout(() => setIsActive(false), GLITCH.burstDuration);
    }, [reduced]);

    const scheduleNextGlitch = useCallback(() => {
        if (interval <= 0 || reduced) return;

        const randomDelay =
            GLITCH.intervalMin + Math.random() * (GLITCH.intervalMax - GLITCH.intervalMin);

        timerRef.current = setTimeout(() => {
            triggerGlitch();
            scheduleNextGlitch();
        }, randomDelay);
    }, [interval, triggerGlitch, reduced]);

    useEffect(() => {
        if (interval <= 0 || reduced) return;

        scheduleNextGlitch();

        return () => {
            if (timerRef.current) clearTimeout(timerRef.current);
            if (burstRef.current) clearTimeout(burstRef.current);
        };
    }, [interval, scheduleNextGlitch, reduced]);

    return (
        <Tag
            className={`glitch-text ${isActive ? 'glitch-active' : ''} ${className}`}
            data-text={children}
            onMouseEnter={triggerGlitch}
        >
            {children}
        </Tag>
    );
}
