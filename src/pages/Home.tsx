import Layout from '@components/layout/Layout';
import Hero from '@components/home/Hero';
import Features from '@components/home/Features';
import HowItWorks from '@components/home/HowItWorks';
import VulnerabilityTypes from '@components/home/VulnerabilityTypes';
import CTA from '@components/home/CTA';

export default function Home() {
    return (
        <Layout>
            <div className="relative z-10">
                <Hero />
                <Features />
                <HowItWorks />
                <VulnerabilityTypes />
                <CTA />
            </div>
        </Layout>
    );
}
