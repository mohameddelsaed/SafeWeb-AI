import { Children, cloneElement, isValidElement, ReactElement } from 'react';

interface PageRevealProps {
    children: React.ReactNode;
    /** Enable staggered reveal for direct children (default: false) */
    stagger?: boolean;
    /** Delay between child reveals in ms (default: 80) */
    staggerDelay?: number;
    className?: string;
}

export default function PageReveal({
    children,
    stagger = false,
    staggerDelay = 80,
    className = '',
}: PageRevealProps) {
    const childArray = Children.toArray(children);

    return (
        <div className={className}>
            {childArray.map((child, index) => {
                const delay = stagger ? index * staggerDelay : 0;
                const style = stagger ? { animationDelay: `${delay}ms` } : undefined;
                return renderChild(child, index, style);
            })}
        </div>
    );
}

function renderChild(child: React.ReactNode, index: number, style?: React.CSSProperties) {
    if (isValidElement(child)) {
        return cloneElement(child as ReactElement, {
            key: index,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            className: `animate-page-enter ${(child.props as any).className || ''}`,
            style: {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ...((child.props as any).style || {}),
                ...style,
            },
        });
    }

    return (
        <div key={index} className="animate-page-enter" style={style}>
            {child}
        </div>
    );
}
