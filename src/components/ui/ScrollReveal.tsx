import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { SCROLL_REVEAL, prefersReducedMotion } from '@utils/animationConfig';

interface ScrollRevealProps {
    children: ReactNode;
    /** Enable staggered reveal for direct children */
    stagger?: boolean;
    /** Delay between child reveals in ms (default: from config) */
    staggerDelay?: number;
    /** Extra delay before the first animation (ms) */
    delay?: number;
    /** Direction to slide from */
    direction?: 'up' | 'down' | 'left' | 'right';
    /** Custom className on the outer wrapper */
    className?: string;
    /** HTML tag for the wrapper */
    as?: keyof JSX.IntrinsicElements;
}

export default function ScrollReveal({
    children,
    stagger = false,
    staggerDelay = SCROLL_REVEAL.stagger,
    delay = 0,
    direction = 'up',
    className = '',
    as: Tag = 'div',
}: ScrollRevealProps) {
    const ref = useRef<HTMLDivElement>(null);
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        if (prefersReducedMotion()) {
            setIsVisible(true);
            return;
        }

        const el = ref.current;
        if (!el) return;

        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    setIsVisible(true);
                    observer.unobserve(el);
                }
            },
            {
                threshold: SCROLL_REVEAL.threshold,
                rootMargin: SCROLL_REVEAL.rootMargin,
            },
        );

        observer.observe(el);
        return () => observer.disconnect();
    }, []);

    const getTransform = (): string => {
        const d = SCROLL_REVEAL.translateY;
        switch (direction) {
            case 'up': return `translateY(${d}px)`;
            case 'down': return `translateY(-${d}px)`;
            case 'left': return `translateX(${d}px)`;
            case 'right': return `translateX(-${d}px)`;
        }
    };

    const baseStyle: CSSProperties = {
        opacity: isVisible ? 1 : SCROLL_REVEAL.opacityStart,
        transform: isVisible ? 'translate(0, 0)' : getTransform(),
        transition: `opacity ${SCROLL_REVEAL.duration}ms ${SCROLL_REVEAL.easing}, transform ${SCROLL_REVEAL.duration}ms ${SCROLL_REVEAL.easing}`,
        transitionDelay: `${delay}ms`,
    };

    // If stagger mode, wrap each child individually
    if (stagger) {
        const childArray = Array.isArray(children) ? children : [children];
        return (
            // @ts-expect-error — dynamic tag
            <Tag ref={ref} className={className}>
                {childArray.map((child, i) => (
                    <div
                        key={i}
                        style={{
                            ...baseStyle,
                            transitionDelay: `${delay + i * staggerDelay}ms`,
                        }}
                    >
                        {child}
                    </div>
                ))}
            </Tag>
        );
    }

    return (
        // @ts-expect-error — dynamic tag
        <Tag ref={ref} className={className} style={baseStyle}>
            {children}
        </Tag>
    );
}
