import type { InputProps } from '../../types/components';

export default function Input({
    label,
    error,
    helperText,
    leftIcon,
    rightIcon,
    className = '',
    id,
    ...props
}: InputProps) {
    // Generate id from id prop, name prop, or label
    const inputId = id || props.name || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);
    
    const baseClasses = 'w-full bg-bg-secondary border border-border-primary rounded-lg px-4 py-2.5 text-text-primary placeholder:text-text-muted transition-colors duration-200 focus:outline-none focus:border-accent-green focus:ring-1 focus:ring-accent-green';
    const errorClasses = error ? 'border-status-critical focus:border-status-critical focus:ring-status-critical' : '';
    const withIconClasses = leftIcon ? 'pl-11' : rightIcon ? 'pr-11' : '';

    return (
        <div className={`w-full ${className}`}>
            {label && (
                <label htmlFor={inputId} className="block text-sm font-medium text-text-secondary mb-2">
                    {label}
                </label>
            )}

            <div className="relative">
                {leftIcon && (
                    <div className="absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary">
                        {leftIcon}
                    </div>
                )}

                <input
                    id={inputId}
                    className={`${baseClasses} ${errorClasses} ${withIconClasses}`}
                    {...props}
                />

                {rightIcon && (
                    <div className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary">
                        {rightIcon}
                    </div>
                )}
            </div>

            {error && (
                <p className="mt-1.5 text-sm text-status-critical">{error}</p>
            )}

            {helperText && !error && (
                <p className="mt-1.5 text-sm text-text-tertiary">{helperText}</p>
            )}
        </div>
    );
}
