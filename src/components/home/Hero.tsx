import { Link } from 'react-router-dom';
import Button from '@components/ui/Button';
import Container from '@components/ui/Container';
import GlitchText from '@components/ui/GlitchText';
import TypewriterText from '@components/ui/TypewriterText';
import ScrollReveal from '@components/ui/ScrollReveal';
import { useLanguage } from '@/contexts/LanguageContext';

export default function Hero() {
    const { t } = useLanguage();

    return (
        <section className="relative py-20 md:py-32 overflow-hidden">
            <Container>
                <div className="max-w-4xl mx-auto text-center">
                    {/* Badge */}
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accent-green/10 border border-accent-green/20 mb-8">
                        <span className="w-2 h-2 bg-accent-green rounded-full animate-pulse"></span>
                        <span className="text-sm font-medium text-accent-green">
                            {t.home.badge}
                        </span>
                    </div>

                    {/* Main Heading */}
                    <h1 className="text-5xl md:text-6xl lg:text-7xl font-heading font-bold text-text-primary mb-6 leading-tight">
                        <GlitchText as="span" interval={8000}>{t.home.titlePart1}</GlitchText>
                        <br />
                        <span className="text-gradient-green">{t.home.titlePart2}</span> {t.home.titlePart3}
                    </h1>

                    {/* Typewriter Tagline */}
                    <div className="h-8 mb-4 flex items-center justify-center">
                        <TypewriterText
                            text="$ safeweb-ai --scan --protect --defend"
                            speed={40}
                            startDelay={800}
                            className="text-sm md:text-base text-accent-green/80"
                        />
                    </div>

                    {/* Description */}
                    <p className="text-lg md:text-xl text-text-secondary max-w-2xl mx-auto mb-10 leading-relaxed">
                        {t.home.desc}
                    </p>

                    {/* CTA Buttons */}
                    <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
                        <Link to="/register">
                            <Button variant="primary" size="lg" className="w-full sm:w-auto">
                                {t.home.startFreeScan}
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                                </svg>
                            </Button>
                        </Link>
                        <Link to="/docs">
                            <Button variant="outline" size="lg" className="w-full sm:w-auto">
                                {t.home.exploreDocs}
                            </Button>
                        </Link>
                    </div>

                    {/* Stats */}
                    <ScrollReveal delay={400}>
                        <div className="grid grid-cols-3 gap-8 max-w-2xl mx-auto pt-8 border-t border-border-primary">
                            <div>
                                <div className="text-3xl md:text-4xl font-bold text-accent-green mb-2">10K+</div>
                                <div className="text-sm text-text-tertiary">Scans Completed</div>
                            </div>
                            <div>
                                <div className="text-3xl md:text-4xl font-bold text-accent-blue mb-2">50K+</div>
                                <div className="text-sm text-text-tertiary">Vulnerabilities Found</div>
                            </div>
                            <div>
                                <div className="text-3xl md:text-4xl font-bold text-accent-green mb-2">99.9%</div>
                                <div className="text-sm text-text-tertiary">Detection Accuracy</div>
                            </div>
                        </div>
                    </ScrollReveal>
                </div>
            </Container>

            {/* Gradient Orbs */}
            <div className="absolute top-1/4 left-10 w-72 h-72 bg-accent-green/10 rounded-full blur-3xl pointer-events-none"></div>
            <div className="absolute bottom-1/4 right-10 w-96 h-96 bg-accent-blue/10 rounded-full blur-3xl pointer-events-none"></div>
        </section>
    );
}
