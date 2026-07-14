import { useEffect, useRef, useCallback } from 'react';
import { TERMINAL, ANIM_COLORS, prefersReducedMotion } from '@utils/animationConfig';

interface Column {
    x: number;
    y: number;
    speed: number;
    charIndex: number;
    lineIndex: number;
}

export default function TerminalBackground() {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const rafRef = useRef<number>(0);
    const columnsRef = useRef<Column[]>([]);
    const reducedMotion = useRef(false);

    const initColumns = useCallback((width: number, height: number) => {
        const cols: Column[] = [];
        const colCount = Math.floor(width / (TERMINAL.columnWidth * 8));
        const [minSpeed, maxSpeed] = TERMINAL.speedRange;

        for (let i = 0; i < colCount; i++) {
            cols.push({
                x: i * (width / colCount),
                y: Math.random() * height * 2 - height,
                speed: minSpeed + Math.random() * (maxSpeed - minSpeed),
                charIndex: Math.floor(Math.random() * 40),
                lineIndex: Math.floor(Math.random() * TERMINAL.lines.length),
            });
        }
        columnsRef.current = cols;
    }, []);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        reducedMotion.current = prefersReducedMotion();
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const resize = () => {
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            canvas.style.width = `${window.innerWidth}px`;
            canvas.style.height = `${window.innerHeight}px`;
            ctx.scale(dpr, dpr);
            initColumns(window.innerWidth, window.innerHeight);
        };

        resize();
        window.addEventListener('resize', resize);

        const lineHeight = TERMINAL.fontSize * 1.6;
        const linesPerColumn = 12;

        const draw = () => {
            if (reducedMotion.current) {
                // Draw once, static
                ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
                ctx.font = `${TERMINAL.fontSize}px "JetBrains Mono", "Fira Code", monospace`;
                ctx.fillStyle = ANIM_COLORS.terminal;
                ctx.globalAlpha = 0.5;

                columnsRef.current.forEach((col) => {
                    for (let j = 0; j < linesPerColumn; j++) {
                        const lineIdx = (col.lineIndex + j) % TERMINAL.lines.length;
                        const text = TERMINAL.lines[lineIdx];
                        ctx.fillText(text, col.x, j * lineHeight + lineHeight);
                    }
                });
                return;
            }

            ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
            ctx.font = `${TERMINAL.fontSize}px "JetBrains Mono", "Fira Code", monospace`;
            ctx.fillStyle = ANIM_COLORS.terminal;
            ctx.globalAlpha = 0.5;

            const viewHeight = window.innerHeight;

            columnsRef.current.forEach((col) => {
                const totalHeight = linesPerColumn * lineHeight;

                for (let j = 0; j < linesPerColumn; j++) {
                    const lineIdx = (col.lineIndex + j) % TERMINAL.lines.length;
                    const text = TERMINAL.lines[lineIdx];
                    const yPos = col.y + j * lineHeight;
                    if (yPos > -lineHeight && yPos < viewHeight + lineHeight) {
                        ctx.fillText(text, col.x, yPos);
                    }
                }

                col.y -= col.speed;

                if (col.y + totalHeight < 0) {
                    col.y = viewHeight + Math.random() * 100;
                    col.lineIndex = (col.lineIndex + linesPerColumn) % TERMINAL.lines.length;
                }
            });

            rafRef.current = requestAnimationFrame(draw);
        };

        rafRef.current = requestAnimationFrame(draw);

        return () => {
            cancelAnimationFrame(rafRef.current);
            window.removeEventListener('resize', resize);
        };
    }, [initColumns]);

    return (
        <canvas
            ref={canvasRef}
            className="fixed inset-0 z-0 pointer-events-none select-none"
            style={{
                opacity: TERMINAL.opacity,
                filter: `blur(${TERMINAL.blur}px)`,
            }}
            aria-hidden="true"
        />
    );
}
