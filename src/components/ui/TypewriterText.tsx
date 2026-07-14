import { type CSSProperties, useEffect, useMemo, useState } from 'react';
import { TYPEWRITER, prefersReducedMotion } from '@utils/animationConfig';

interface TypewriterTextProps {
    text: string;
    /** Typing speed in ms per character */
    speed?: number;
    /** Delay before typing starts in ms */
    startDelay?: number;
    /** Hide cursor after typing completes */
    hideCursorOnComplete?: boolean;
    className?: string;
}

export default function TypewriterText({
    text,
    speed = TYPEWRITER.speed,
    startDelay = TYPEWRITER.startDelay,
    hideCursorOnComplete = false,
    className = '',
}: TypewriterTextProps) {
    const reduced = prefersReducedMotion();
    const characters = Math.max(text.length, 1);
    const typingDuration = characters * speed;
    const [isComplete, setIsComplete] = useState(reduced);

    useEffect(() => {
        if (reduced) {
            setIsComplete(true);
            return;
        }
        setIsComplete(false);
        const totalDuration = typingDuration + startDelay;
        const timer = window.setTimeout(() => setIsComplete(true), totalDuration);
        return () => window.clearTimeout(timer);
    }, [text, typingDuration, startDelay, reduced]);

    const trackStyle = useMemo(
        () => ({
            '--typewriter-width': `${characters}ch`,
        }) as CSSProperties,
        [characters],
    );

    // If reduced motion, show the text immediately with no animation
    if (reduced) {
        return (
            <span className={`font-mono ${className}`}>
                {text}
            </span>
        );
    }

    return (
        <span className={`typewriter-wrapper font-mono ${className}`}>
            <span className="sr-only">{text}</span>
            <span
                className="typewriter-track"
                style={trackStyle}
                aria-hidden="true"
            >
                <span
                    className="typewriter-text"
                    style={{
                        animationDelay: `${startDelay}ms`,
                        animationDuration: `${typingDuration}ms`,
                        animationTimingFunction: `steps(${characters})`,
                    }}
                >
                    {text}
                </span>
                <span
                    className={`typewriter-cursor${isComplete && hideCursorOnComplete ? ' typewriter-cursor--hidden' : ''}`}
                    style={{ animationDelay: `${startDelay}ms` }}
                    aria-hidden="true"
                />
            </span>
        </span>
    );
}
