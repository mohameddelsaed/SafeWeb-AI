import type { SelectProps } from '../../types/components';

export default function Select({
    label,
    error,
    helperText,
    options,
    className = '',
    id,
    ...props
}: SelectProps) {
    // Generate id from label if not provided
    const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);
    
    const baseClasses = 'w-full bg-bg-secondary border border-border-primary rounded-lg px-4 py-2.5 text-text-primary transition-colors duration-200 focus:outline-none focus:border-accent-green focus:ring-1 focus:ring-accent-green cursor-pointer';
    const errorClasses = error ? 'border-status-critical focus:border-status-critical focus:ring-status-critical' : '';

    return (
        <div className={`w-full ${className}`}>
            {label && (
                <label htmlFor={selectId} className="block text-sm font-medium text-text-secondary mb-2">
                    {label}
                </label>
            )}

            <select
                id={selectId}
                className={`${baseClasses} ${errorClasses}`}
                {...props}
            >
                {options.map((option) => (
                    <option key={option.value} value={option.value} className="bg-bg-secondary">
                        {option.label}
                    </option>
                ))}
            </select>

            {error && (
                <p className="mt-1.5 text-sm text-status-critical">{error}</p>
            )}

            {helperText && !error && (
                <p className="mt-1.5 text-sm text-text-tertiary">{helperText}</p>
            )}
        </div>
    );
}
