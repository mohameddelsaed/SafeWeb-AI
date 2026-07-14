import Navbar from './Navbar';
import Footer from './Footer';
import TerminalBackground from '@components/home/TerminalBackground';
import PageWrapper from '@components/ui/PageWrapper';

interface LayoutProps {
    children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
    return (
        <div className="min-h-screen flex flex-col bg-bg-primary">
            <TerminalBackground />
            <Navbar />
            <main className="flex-1 pt-20 relative z-10">
                <PageWrapper>
                    {children}
                </PageWrapper>
            </main>
            <div className="relative z-10">
                <Footer />
            </div>
        </div>
    );
}
