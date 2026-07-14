import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import { careersAPI } from '@services/api';

export default function Careers() {
    const [selectedJob, setSelectedJob] = useState<string | null>(null);
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        phone: '',
        coverLetter: '',
        resumeUrl: '',
        portfolioUrl: '',
    });
    const [submitStatus, setSubmitStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
    const [submitMessage, setSubmitMessage] = useState('');

    const openings = [
        {
            title: 'Senior Security Engineer',
            department: 'Engineering',
            location: 'Remote',
            type: 'Full-time',
            description: 'Design and implement advanced vulnerability detection algorithms. Work on our core scanning engine and improve detection accuracy.',
        },
        {
            title: 'Machine Learning Engineer',
            department: 'AI / ML',
            location: 'Remote',
            type: 'Full-time',
            description: 'Build and train models that identify zero-day vulnerabilities and predict emerging threat patterns across web applications.',
        },
        {
            title: 'Full-Stack Developer',
            department: 'Engineering',
            location: 'Remote',
            type: 'Full-time',
            description: 'Build user-facing features using React and Django. Contribute to our dashboard, reporting, and scan management systems.',
        },
        {
            title: 'DevOps Engineer',
            department: 'Infrastructure',
            location: 'Remote',
            type: 'Full-time',
            description: 'Manage cloud infrastructure, CI/CD pipelines, and monitoring systems that power the SafeWeb AI platform.',
        },
        {
            title: 'Technical Writer',
            department: 'Product',
            location: 'Remote',
            type: 'Part-time',
            description: 'Create clear, comprehensive documentation for our API, user guides, and security best-practices blog.',
        },
    ];

    const benefits = [
        { icon: '🌍', title: 'Fully Remote', desc: 'Work from anywhere in the world' },
        { icon: '📈', title: 'Equity', desc: 'Stock options for all employees' },
        { icon: '🏥', title: 'Health Insurance', desc: 'Comprehensive medical, dental & vision' },
        { icon: '📚', title: 'Learning Budget', desc: '$2,000/year for courses & conferences' },
        { icon: '🏖️', title: 'Unlimited PTO', desc: 'Take time off when you need it' },
        { icon: '💻', title: 'Equipment Stipend', desc: 'Top-of-the-line hardware & setup' },
    ];

    const handleApply = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedJob) return;

        setSubmitStatus('loading');
        try {
            const res = await careersAPI.apply({
                position: selectedJob,
                name: formData.name,
                email: formData.email,
                phone: formData.phone || undefined,
                coverLetter: formData.coverLetter || undefined,
                resumeUrl: formData.resumeUrl || undefined,
                portfolioUrl: formData.portfolioUrl || undefined,
            });
            setSubmitStatus('success');
            setSubmitMessage(res.data?.detail || 'Application submitted successfully!');
            setFormData({ name: '', email: '', phone: '', coverLetter: '', resumeUrl: '', portfolioUrl: '' });
            setSelectedJob(null);
        } catch (err: unknown) {
            setSubmitStatus('error');
            const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
            setSubmitMessage(msg || 'Failed to submit application. Please try again.');
        }
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="max-w-4xl mx-auto">
                        {/* Header */}
                        <div className="text-center mb-12">
                            <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                                Careers at SafeWeb AI
                            </h1>
                            <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                                Join our mission to make the internet safer. We&apos;re building AI-powered security tools that protect millions of websites worldwide.
                            </p>
                        </div>

                        {/* Status Messages */}
                        {submitStatus === 'success' && (
                            <div className="mb-6 p-4 rounded-lg bg-accent-green/10 border border-accent-green/30 text-accent-green text-center">
                                {submitMessage}
                            </div>
                        )}
                        {submitStatus === 'error' && (
                            <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-center">
                                {submitMessage}
                            </div>
                        )}

                        {/* Benefits */}
                        <Card className="p-8 mb-10">
                            <h2 className="text-2xl font-heading font-semibold text-text-primary mb-6 text-center">
                                Why Join Us?
                            </h2>
                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
                                {benefits.map((b) => (
                                    <div key={b.title} className="text-center">
                                        <div className="text-3xl mb-2">{b.icon}</div>
                                        <h3 className="font-semibold text-text-primary">{b.title}</h3>
                                        <p className="text-sm text-text-secondary">{b.desc}</p>
                                    </div>
                                ))}
                            </div>
                        </Card>

                        {/* Open Positions */}
                        <h2 className="text-2xl font-heading font-semibold text-text-primary mb-6">
                            Open Positions
                        </h2>
                        <div className="space-y-4">
                            {openings.map((job) => (
                                <Card key={job.title} className="p-6 hover:border-accent-green/30 transition-colors">
                                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                                        <div className="flex-1">
                                            <h3 className="text-lg font-semibold text-text-primary mb-1">{job.title}</h3>
                                            <p className="text-sm text-text-secondary mb-3">{job.description}</p>
                                            <div className="flex flex-wrap gap-2">
                                                <Badge variant="info">{job.department}</Badge>
                                                <Badge variant="default">{job.location}</Badge>
                                                <Badge variant="success">{job.type}</Badge>
                                            </div>
                                        </div>
                                        <Button
                                            variant="primary"
                                            size="sm"
                                            onClick={() => {
                                                setSelectedJob(job.title);
                                                setSubmitStatus('idle');
                                            }}
                                        >
                                            Apply Now
                                        </Button>
                                    </div>

                                    {/* Application Form — shown inline */}
                                    {selectedJob === job.title && (
                                        <form onSubmit={handleApply} className="mt-6 pt-6 border-t border-border-primary space-y-4">
                                            <h4 className="font-semibold text-text-primary">Apply for {job.title}</h4>
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                <Input
                                                    label="Full Name *"
                                                    value={formData.name}
                                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                                    required
                                                />
                                                <Input
                                                    label="Email *"
                                                    type="email"
                                                    value={formData.email}
                                                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                                    required
                                                />
                                                <Input
                                                    label="Phone"
                                                    value={formData.phone}
                                                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                                                />
                                                <Input
                                                    label="Portfolio / LinkedIn URL"
                                                    value={formData.portfolioUrl}
                                                    onChange={(e) => setFormData({ ...formData, portfolioUrl: e.target.value })}
                                                    placeholder="https://..."
                                                />
                                            </div>
                                            <Input
                                                label="Resume URL"
                                                value={formData.resumeUrl}
                                                onChange={(e) => setFormData({ ...formData, resumeUrl: e.target.value })}
                                                placeholder="Link to your resume (Google Drive, Dropbox, etc.)"
                                            />
                                            <div>
                                                <label className="block text-sm font-medium text-text-secondary mb-1">Cover Letter</label>
                                                <textarea
                                                    className="w-full min-h-[120px] px-4 py-3 rounded-xl bg-bg-secondary border border-border-primary text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent-green/40"
                                                    value={formData.coverLetter}
                                                    onChange={(e) => setFormData({ ...formData, coverLetter: e.target.value })}
                                                    placeholder="Tell us why you'd be great for this role..."
                                                />
                                            </div>
                                            <div className="flex gap-3">
                                                <Button type="submit" variant="primary" disabled={submitStatus === 'loading'}>
                                                    {submitStatus === 'loading' ? 'Submitting...' : 'Submit Application'}
                                                </Button>
                                                <Button type="button" variant="ghost" onClick={() => setSelectedJob(null)}>
                                                    Cancel
                                                </Button>
                                            </div>
                                        </form>
                                    )}
                                </Card>
                            ))}
                        </div>

                        {/* General Application */}
                        <Card className="mt-10 p-8 text-center bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                            <h2 className="text-2xl font-heading font-semibold text-text-primary mb-3">
                                Don&apos;t see a match?
                            </h2>
                            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
                                We&apos;re always looking for talented people. Send your résumé and a brief intro — we&apos;d love to hear from you.
                            </p>
                            <Button
                                variant="primary"
                                onClick={() => {
                                    setSelectedJob('General Application');
                                    setSubmitStatus('idle');
                                    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
                                }}
                            >
                                Send General Application
                            </Button>

                            {selectedJob === 'General Application' && (
                                <form onSubmit={handleApply} className="mt-6 pt-6 border-t border-border-primary space-y-4 text-left max-w-lg mx-auto">
                                    <h4 className="font-semibold text-text-primary">General Application</h4>
                                    <Input
                                        label="Full Name *"
                                        value={formData.name}
                                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                        required
                                    />
                                    <Input
                                        label="Email *"
                                        type="email"
                                        value={formData.email}
                                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                        required
                                    />
                                    <Input
                                        label="Phone"
                                        value={formData.phone}
                                        onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                                    />
                                    <Input
                                        label="Resume / Portfolio URL"
                                        value={formData.resumeUrl}
                                        onChange={(e) => setFormData({ ...formData, resumeUrl: e.target.value })}
                                        placeholder="https://..."
                                    />
                                    <div>
                                        <label className="block text-sm font-medium text-text-secondary mb-1">Tell us about yourself</label>
                                        <textarea
                                            className="w-full min-h-[120px] px-4 py-3 rounded-xl bg-bg-secondary border border-border-primary text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent-green/40"
                                            value={formData.coverLetter}
                                            onChange={(e) => setFormData({ ...formData, coverLetter: e.target.value })}
                                            placeholder="Tell us about your background and what you'd like to work on..."
                                        />
                                    </div>
                                    <div className="flex gap-3 justify-center">
                                        <Button type="submit" variant="primary" disabled={submitStatus === 'loading'}>
                                            {submitStatus === 'loading' ? 'Submitting...' : 'Submit Application'}
                                        </Button>
                                        <Button type="button" variant="ghost" onClick={() => setSelectedJob(null)}>
                                            Cancel
                                        </Button>
                                    </div>
                                </form>
                            )}
                        </Card>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
