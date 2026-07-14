export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    children?: React.ReactNode;
    variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
    size?: 'sm' | 'md' | 'lg';
    isLoading?: boolean;
    leftIcon?: React.ReactNode;
    rightIcon?: React.ReactNode;
}

export interface CardProps {
    children: React.ReactNode;
    className?: string;
    variant?: 'default' | 'glass' | 'bordered';
    hover?: boolean;
    glow?: 'none' | 'green' | 'blue';
    id?: string;
    onClick?: () => void;
}

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    error?: string;
    helperText?: string;
    leftIcon?: React.ReactNode;
    rightIcon?: React.ReactNode;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
    label?: string;
    error?: string;
    helperText?: string;
    options: Array<{ value: string; label: string }>;
}

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
    label?: string;
    error?: string;
    helperText?: string;
}

export interface BadgeProps {
    children: React.ReactNode;
    variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'default' | 'success';
    size?: 'sm' | 'md';
}

export interface ContainerProps {
    children: React.ReactNode;
    className?: string;
    maxWidth?: 'container' | 'content' | 'full';
}
