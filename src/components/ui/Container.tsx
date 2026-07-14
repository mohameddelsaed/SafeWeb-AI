import type { ContainerProps } from '../../types/components';

export default function Container({
    children,
    className = '',
    maxWidth = 'container',
}: ContainerProps) {
    const maxWidthClasses = {
        container: 'max-w-container',
        content: 'max-w-content',
        full: 'max-w-full',
    };

    return (
        <div className={`w-full ${maxWidthClasses[maxWidth]} mx-auto px-6 ${className}`}>
            {children}
        </div>
    );
}
