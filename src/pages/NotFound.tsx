import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Button from '@components/ui/Button';

export default function NotFound() {
    return (
        <Layout>
            <div className="py-20 min-h-screen flex items-center">
                <Container>
                    <div className="text-center max-w-lg mx-auto">
                        <h1 className="text-8xl font-heading font-bold text-accent-green mb-4">404</h1>
                        <h2 className="text-2xl font-heading font-bold text-text-primary mb-4">
                            Page Not Found
                        </h2>
                        <p className="text-text-secondary mb-8">
                            The page you&apos;re looking for doesn&apos;t exist or has been moved.
                        </p>
                        <Link to="/">
                            <Button variant="primary" size="lg">
                                Back to Home
                            </Button>
                        </Link>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
