import { Link } from 'react-router-dom';
import Button from '@components/ui/Button';
import Container from '@components/ui/Container';
import GlitchText from '@components/ui/GlitchText';
import ScrollReveal from '@components/ui/ScrollReveal';

export default function CTA() {
    return (
        <section className="py-20">
            <Container>
                <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-accent-green/10 via-accent-blue/10 to-accent-green/5 border border-accent-green/20 p-12 md:p-16">
                    {/* Background Pattern */}
                    <div className="absolute inset-0 opacity-5">
                        <div className="absolute inset-0" style={{
                            backgroundImage: `repeating-linear-gradient(0deg, #00FF88 0px, #00FF88 1px, transparent 1px, transparent 40px),
                               repeating-linear-gradient(90deg, #00FF88 0px, #00FF88 1px, transparent 1px, transparent 40px)`
                        }}></div>
                    </div>

                    <div className="relative z-10 max-w-3xl mx-auto text-center">
                        <ScrollReveal>
                        <h2 className="text-3xl md:text-4xl lg:text-5xl font-heading font-bold text-text-primary mb-6">
                            <GlitchText as="span" interval={6000}>Ready to Secure Your Web Applications?</GlitchText>
                        </h2>
                        <p className="text-lg md:text-xl text-text-secondary mb-10">
                            Start scanning for free. No credit card required. Get instant security insights
                            and protect your digital assets today.
                        </p>

                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                            <Link to="/register">
                                <Button variant="primary" size="lg" className="w-full sm:w-auto">
                                    Get Started for Free
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                                    </svg>
                                </Button>
                            </Link>
                            <Link to="/contact">
                                <Button variant="outline" size="lg" className="w-full sm:w-auto">
                                    Contact Sales
                                </Button>
                            </Link>
                        </div>

                        <div className="mt-10 flex items-center justify-center gap-8 text-sm text-text-tertiary">
                            <div className="flex items-center gap-2">
                                <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                <span>No credit card</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                <span>Free tier available</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <svg className="w-5 h-5 text-accent-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                <span>Cancel anytime</span>
                            </div>
                        </div>
                        </ScrollReveal>
                    </div>

                    {/* Decorative Elements */}
                    <div className="absolute top-0 right-0 w-64 h-64 bg-accent-green/5 rounded-full blur-3xl pointer-events-none"></div>
                    <div className="absolute bottom-0 left-0 w-64 h-64 bg-accent-blue/5 rounded-full blur-3xl pointer-events-none"></div>
                </div>
            </Container>
        </section>
    );
}
