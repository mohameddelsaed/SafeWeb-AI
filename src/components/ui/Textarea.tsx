import type { TextareaProps } from '../../types/components';

export default function Textarea({
    label,
    error,
    helperText,
    className = '',
    id,
    ...props
}: TextareaProps) {
    // Generate id from label if not provided
    const textareaId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);
    
    const baseClasses = 'w-full bg-bg-secondary border border-border-primary rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted transition-colors duration-200 focus:outline-none focus:border-accent-green focus:ring-1 focus:ring-accent-green resize-none';
    const errorClasses = error ? 'border-status-critical focus:border-status-critical focus:ring-status-critical' : '';

    return (
        <div className={`w-full ${className}`}>
            {label && (
                <label htmlFor={textareaId} className="block text-sm font-medium text-text-secondary mb-2">
                    {label}
                </label>
            )}

            <textarea
                id={textareaId}
                className={`${baseClasses} ${errorClasses}`}
                {...props}
            />

            {error && (
                <p className="mt-1.5 text-sm text-status-critical">{error}</p>
            )}

            {helperText && !error && (
                <p className="mt-1.5 text-sm text-text-tertiary">{helperText}</p>
            )}
        </div>
    );
}
