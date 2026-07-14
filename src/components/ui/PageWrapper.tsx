import { prefersReducedMotion } from '@utils/animationConfig';

interface PageWrapperProps {
    children: React.ReactNode;
    className?: string;
}

export default function PageWrapper({ children, className = '' }: PageWrapperProps) {
    const reduced = prefersReducedMotion();
    return (
        <div className={`${reduced ? '' : 'animate-page-enter'} ${className}`}>
            {children}
        </div>
    );
}
