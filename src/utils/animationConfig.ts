/**
 * Centralised animation configuration for SafeWeb AI.
 *
 * Every timing value, easing curve, and colour constant used by the
 * animation system lives here so changes propagate globally.
 */

// ── Timing ──────────────────────────────────────────────────────────
export const TIMING = {
    /** Micro-interactions: button press, badge pulse trigger */
    micro: 120,
    /** Standard hover / focus transitions (ms) */
    hover: 200,
    /** Component transitions: card lift, drawer open (ms) */
    component: 300,
    /** Page-level entrance animation (ms) */
    pageEnter: 500,
    /** Stagger delay between sibling reveals (ms) */
    stagger: 80,
} as const;

// ── Easing ──────────────────────────────────────────────────────────
export const EASING = {
    /** Default ease-out for most transitions */
    default: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)',
    /** Snappy ease for button / micro interactions */
    snappy: 'cubic-bezier(0.22, 1, 0.36, 1)',
    /** Smooth deceleration for page entrance */
    decel: 'cubic-bezier(0, 0, 0.2, 1)',
    /** Spring-like ease for bouncy interactions */
    spring: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
} as const;

// ── Colours (animation-specific) ────────────────────────────────────
export const ANIM_COLORS = {
    /** Primary neon green */
    green: '#00FF88',
    /** Accent blue */
    blue: '#3AA9FF',
    /** Danger / error red */
    red: '#FF3B3B',
    /** Terminal text colour */
    terminal: '#00FF88',
    /** Glitch channel A (cyan-green) */
    glitchA: '#00FF88',
    /** Glitch channel B (blue accent) */
    glitchB: '#3AA9FF',
    /** Glitch channel C (red accent – subtle) */
    glitchC: '#FF3B3B',
} as const;

// ── Glitch Text ─────────────────────────────────────────────────────
export const GLITCH = {
    /** Duration of single glitch burst (ms) */
    burstDuration: 120,
    /** Min interval between auto-glitches (ms) */
    intervalMin: 8_000,
    /** Max interval between auto-glitches (ms) */
    intervalMax: 15_000,
    /** Pseudo-element opacity when glitching */
    layerOpacity: 0.55,
} as const;

// ── Typewriter ──────────────────────────────────────────────────────
export const TYPEWRITER = {
    /** Default ms per character */
    speed: 38,
    /** Delay before typing begins (ms) */
    startDelay: 300,
    /** Cursor blink interval (ms) */
    cursorBlink: 1000,
} as const;

// ── Terminal Background (Canvas) ────────────────────────────────────
export const TERMINAL = {
    /** Font size in px for canvas text */
    fontSize: 11,
    /** Column spacing multiplier (px) */
    columnWidth: 14,
    /** Fall speed range [min, max] px per frame at 60 fps */
    speedRange: [0.3, 0.8] as readonly [number, number],
    /** Global canvas opacity */
    opacity: 0.06,
    /** Blur applied to canvas (CSS filter) */
    blur: 1.5,
    /** Characters / lines to render */
    lines: [
        '$ nmap -sV --script=vuln target.com',
        '> scanning ports 1-65535...',
        'PORT     STATE  SERVICE    VERSION',
        '22/tcp   open   ssh        OpenSSH 8.9',
        '80/tcp   open   http       nginx 1.24.0',
        '443/tcp  open   ssl/https  nginx 1.24.0',
        '$ sqlmap -u "http://target.com/?id=1"',
        '[INFO] testing connection to target URL',
        '[INFO] checking if target is protected',
        '> payload: OR 1=1--',
        '$ nikto -h target.com -ssl',
        '+ Server: nginx/1.24.0',
        '+ /admin/: Directory indexing found',
        '$ curl -I https://target.com',
        'HTTP/2 200 OK',
        'x-frame-options: DENY',
        'content-security-policy: default-src self',
        '$ gobuster dir -u target.com -w common.txt',
        '/api        (Status: 200) [Size: 1024]',
        '/login      (Status: 200) [Size: 2048]',
        '$ hydra -l admin -P pass.txt ssh',
        '[ATTEMPT] target - login "admin"',
        '[STATUS] 128 tries, 0 success',
        '> vulnerability scan complete',
        '> generating report...',
        'CRITICAL: 2  HIGH: 5  MEDIUM: 12  LOW: 8',
        '$ safeweb-ai --deep-scan --target=*.com',
        '[*] Initializing AI threat engine...',
        '[*] Loading vulnerability signatures...',
        '[+] Scan started at 2026-02-14T09:00:00Z',
    ],
} as const;

// ── Page Entrance ───────────────────────────────────────────────────
export const PAGE_ENTER = {
    /** Y offset in px to slide from */
    translateY: 8,
    /** Duration in ms */
    duration: TIMING.pageEnter,
    /** Easing curve */
    easing: EASING.decel,
} as const;

// ── Card ────────────────────────────────────────────────────────────
export const CARD = {
    /** Hover translate-Y (px) – negative = up */
    hoverLift: -6,
    /** Transition duration (ms) */
    transitionMs: TIMING.component,
    /** Glow spread on hover */
    glowSpread: '15px',
    /** Border glow opacity on hover */
    borderGlowOpacity: 0.3,
} as const;

// ── Button ──────────────────────────────────────────────────────────
export const BUTTON = {
    /** Hover translate-Y (px) */
    hoverLift: -2,
    /** Active scale factor */
    activeScale: 0.98,
    /** Transition duration (ms) */
    transitionMs: TIMING.hover,
    /** Border-trace animation duration (s) */
    borderTraceSpeed: 2.4,
} as const;

// ── Scroll Reveal ───────────────────────────────────────────────────
export const SCROLL_REVEAL = {
    /** IntersectionObserver threshold */
    threshold: 0.15,
    /** Root margin for early trigger */
    rootMargin: '0px 0px -60px 0px',
    /** Base translate-Y offset (px) */
    translateY: 24,
    /** Base opacity start */
    opacityStart: 0,
    /** Reveal duration (ms) */
    duration: 600,
    /** Stagger delay between children (ms) */
    stagger: TIMING.stagger,
    /** Easing */
    easing: EASING.decel,
} as const;

// ── Prefers-reduced-motion helper ───────────────────────────────────
export function prefersReducedMotion(): boolean {
    if (typeof window === 'undefined') return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
