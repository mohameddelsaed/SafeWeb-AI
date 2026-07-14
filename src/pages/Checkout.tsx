import { useState, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import ScrollReveal from '@components/ui/ScrollReveal';
import { useLanguage } from '@/contexts/LanguageContext';

export default function Checkout() {
    const { t, language } = useLanguage();
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();

    // Parse URL parameters
    const initialPlan = searchParams.get('plan') || 'pro';
    const initialBilling = searchParams.get('billing') || 'annual';

    const [selectedPlan] = useState<'starter' | 'pro' | 'enterprise'>(
        (initialPlan as 'starter' | 'pro' | 'enterprise') || 'pro'
    );
    const [isAnnual, setIsAnnual] = useState<boolean>(initialBilling === 'annual');

    // Payment Method State
    const [paymentMethod, setPaymentMethod] = useState<'card' | 'paypal' | 'crypto'>('card');
    const [cardName, setCardName] = useState('');
    const [cardNumber, setCardNumber] = useState('');
    const [expiry, setExpiry] = useState('');
    const [cvc, setCvc] = useState('');
    const [cryptoCurrency, setCryptoCurrency] = useState('USDT (BEP20)');

    // Promo Code State
    const [promoInput, setPromoInput] = useState('');
    const [promoDiscount, setPromoDiscount] = useState<number>(0);
    const [promoStatus, setPromoStatus] = useState<'none' | 'success' | 'error'>('none');

    // Processing & Success States
    const [isProcessing, setIsProcessing] = useState(false);
    const [isSuccess, setIsSuccess] = useState(false);
    const [invoiceId, setInvoiceId] = useState('');
    const [licenseKey, setLicenseKey] = useState('');

    // Plan Pricing details
    const planDetails = useMemo(() => {
        const plans = {
            starter: {
                title: t.pricing.starterTitle,
                monthlyPrice: 39,
                annualPrice: 390, // 10 months pay (2 months free)
                features: ['5 Monthly Scans', 'Surface & Moderate Depth', 'OWASP Top 10 Coverage'],
            },
            pro: {
                title: t.pricing.proTitle,
                monthlyPrice: 199,
                annualPrice: 1908, // $159 * 12
                features: ['100 Autonomous AI Scans', 'Evidence Verification', 'API & CI/CD Integrations'],
            },
            enterprise: {
                title: t.pricing.enterpriseTitle,
                monthlyPrice: 699,
                annualPrice: 6588, // $549 * 12
                features: ['Unlimited Scans & Wildcards', 'Dedicated Worker Clusters', 'Custom SLAs & RBAC'],
            },
        };
        return plans[selectedPlan] || plans.pro;
    }, [selectedPlan, t.pricing]);

    // Financial calculations
    const subtotal = useMemo(() => {
        return isAnnual ? planDetails.annualPrice : planDetails.monthlyPrice;
    }, [isAnnual, planDetails]);

    const discountAmount = useMemo(() => {
        return Math.round(subtotal * promoDiscount);
    }, [subtotal, promoDiscount]);

    const totalDue = useMemo(() => {
        return subtotal - discountAmount;
    }, [subtotal, discountAmount]);

    // Format Card Input
    const handleCardNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        let val = e.target.value.replace(/\D/g, '');
        if (val.length > 16) val = val.slice(0, 16);
        const formatted = val.match(/.{1,4}/g)?.join(' ') || val;
        setCardNumber(formatted);
    };

    const handleExpiryChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        let val = e.target.value.replace(/\D/g, '');
        if (val.length > 4) val = val.slice(0, 4);
        if (val.length >= 3) {
            val = `${val.slice(0, 2)}/${val.slice(2)}`;
        }
        setExpiry(val);
    };

    const handleCvcChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        let val = e.target.value.replace(/\D/g, '');
        if (val.length > 4) val = val.slice(0, 4);
        setCvc(val);
    };

    // Promo Code Application
    const handleApplyPromo = () => {
        const code = promoInput.trim().toUpperCase();
        if (code === 'GRAD2026' || code === 'SAFEWEB20' || code === 'AI2026' || code === 'OMAR') {
            setPromoDiscount(0.2); // 20% discount
            setPromoStatus('success');
        } else {
            setPromoDiscount(0);
            setPromoStatus('error');
        }
    };

    // Handle Submit Payment
    const handlePaymentSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setIsProcessing(true);

        setTimeout(() => {
            setIsProcessing(false);
            setIsSuccess(true);
            setInvoiceId(`SW-INV-${new Date().getFullYear()}-${Math.floor(100000 + Math.random() * 900000)}`);
            setLicenseKey(`SW-PRO-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`);
        }, 2500);
    };

    if (isSuccess) {
        return (
            <Layout>
                <Container className="py-20">
                    <ScrollReveal>
                        <Card className="max-w-2xl mx-auto p-8 md:p-12 text-center border-2 border-accent-green bg-gradient-to-b from-bg-card via-bg-card to-accent-green/10 shadow-[0_0_50px_rgba(0,240,255,0.2)]">
                            <div className="w-20 h-20 rounded-full bg-accent-green/20 border-2 border-accent-green flex items-center justify-center mx-auto mb-6 animate-bounce">
                                <svg className="w-10 h-10 text-accent-green" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            
                            <span className="px-4 py-1 rounded-full bg-accent-green/20 text-accent-green font-mono text-xs font-bold uppercase tracking-wider mb-4 inline-block">
                                {t.checkout.badge}
                            </span>
                            <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                {t.checkout.successTitle}
                            </h1>
                            <p className="text-text-secondary mb-8 max-w-lg mx-auto">
                                {t.checkout.successSubtitle}
                            </p>

                            <div className="bg-bg-secondary/80 border border-border-primary rounded-xl p-6 mb-8 text-left space-y-4 font-mono text-sm">
                                <div className="flex justify-between items-center pb-3 border-b border-border-primary/50">
                                    <span className="text-text-tertiary">{t.checkout.invoiceId}:</span>
                                    <span className="text-text-primary font-bold">{invoiceId}</span>
                                </div>
                                <div className="flex justify-between items-center pb-3 border-b border-border-primary/50">
                                    <span className="text-text-tertiary">{t.checkout.amountPaid}:</span>
                                    <span className="text-accent-green font-bold text-base">${totalDue} USD ({isAnnual ? 'Annual' : 'Monthly'})</span>
                                </div>
                                <div className="flex justify-between items-center pb-3 border-b border-border-primary/50">
                                    <span className="text-text-tertiary">{t.checkout.licenseKey}:</span>
                                    <span className="text-accent-cyan bg-bg-primary px-3 py-1 rounded border border-accent-cyan/30 tracking-widest">{licenseKey}</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-text-tertiary">{t.checkout.nextBilling}:</span>
                                    <span className="text-text-secondary">
                                        {new Date(Date.now() + (isAnnual ? 365 : 30) * 24 * 60 * 60 * 1000).toLocaleDateString(language === 'ar' ? 'ar-EG' : 'en-US')}
                                    </span>
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row gap-4 justify-center">
                                <Button
                                    variant="primary"
                                    size="lg"
                                    onClick={() => navigate('/dashboard')}
                                    className="shadow-lg shadow-accent-green/25 font-bold"
                                >
                                    {t.checkout.goToDashboard}
                                </Button>
                                <Button
                                    variant="outline"
                                    size="lg"
                                    onClick={() => window.print()}
                                    className="font-mono text-sm"
                                >
                                    {t.checkout.downloadReceipt}
                                </Button>
                            </div>
                        </Card>
                    </ScrollReveal>
                </Container>
            </Layout>
        );
    }

    return (
        <Layout>
            <Container className="py-12 md:py-16">
                {/* Header */}
                <div className="text-center max-w-2xl mx-auto mb-12">
                    <span className="inline-block px-3.5 py-1 rounded-full bg-accent-green/10 border border-accent-green/30 text-accent-green text-xs font-mono font-bold tracking-wider uppercase mb-3">
                        {t.checkout.badge}
                    </span>
                    <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                        {t.checkout.title}
                    </h1>
                    <p className="text-text-secondary text-sm md:text-base">
                        {t.checkout.subtitle}
                    </p>
                </div>

                <form onSubmit={handlePaymentSubmit} className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                    {/* Left Column: Payment Form */}
                    <div className="lg:col-span-7 space-y-6">
                        {/* Step 1: Payment Method Tabs */}
                        <Card className="p-6 md:p-8 border border-border-primary bg-bg-card/90 backdrop-blur">
                            <h2 className="text-lg font-heading font-bold text-text-primary mb-4 flex items-center gap-2">
                                <span className="w-6 h-6 rounded-full bg-accent-green text-bg-primary text-xs flex items-center justify-center font-bold">1</span>
                                {t.checkout.stepPayment}
                            </h2>

                            {/* Express Wallet Buttons */}
                            <div className="mb-6">
                                <div className="text-xs font-mono text-text-tertiary mb-3">{t.checkout.expressCheckout}</div>
                                <div className="grid grid-cols-2 gap-3">
                                    <button
                                        type="button"
                                        onClick={() => setPaymentMethod('card')}
                                        className="py-2.5 px-4 rounded-xl border border-border-primary bg-bg-secondary hover:border-text-primary transition flex items-center justify-center gap-2 font-medium text-sm text-text-primary"
                                    >
                                        <span> Apple Pay</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setPaymentMethod('card')}
                                        className="py-2.5 px-4 rounded-xl border border-border-primary bg-bg-secondary hover:border-text-primary transition flex items-center justify-center gap-2 font-medium text-sm text-text-primary"
                                    >
                                        <span>G Google Pay</span>
                                    </button>
                                </div>
                                <div className="flex items-center gap-3 my-5">
                                    <div className="h-px bg-border-primary flex-1"></div>
                                    <span className="text-xs text-text-tertiary font-mono uppercase">{t.checkout.orPayWithCard}</span>
                                    <div className="h-px bg-border-primary flex-1"></div>
                                </div>
                            </div>

                            {/* Method Selector Tabs */}
                            <div className="grid grid-cols-3 gap-2 p-1.5 rounded-xl bg-bg-secondary border border-border-primary mb-6">
                                <button
                                    type="button"
                                    onClick={() => setPaymentMethod('card')}
                                    className={`py-2 px-3 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 ${
                                        paymentMethod === 'card'
                                            ? 'bg-accent-green text-bg-primary shadow'
                                            : 'text-text-secondary hover:text-text-primary'
                                    }`}
                                >
                                    <span>💳</span> {t.checkout.cardTab}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setPaymentMethod('paypal')}
                                    className={`py-2 px-3 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 ${
                                        paymentMethod === 'paypal'
                                            ? 'bg-accent-green text-bg-primary shadow'
                                            : 'text-text-secondary hover:text-text-primary'
                                    }`}
                                >
                                    <span>🅿️</span> {t.checkout.paypalTab}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setPaymentMethod('crypto')}
                                    className={`py-2 px-3 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 ${
                                        paymentMethod === 'crypto'
                                            ? 'bg-accent-green text-bg-primary shadow'
                                            : 'text-text-secondary hover:text-text-primary'
                                    }`}
                                >
                                    <span>₿</span> {t.checkout.cryptoTab}
                                </button>
                            </div>

                            {/* Card Details Form */}
                            {paymentMethod === 'card' && (
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                            {t.checkout.cardName}
                                        </label>
                                        <Input
                                            type="text"
                                            required
                                            placeholder={t.checkout.cardNamePlaceholder}
                                            value={cardName}
                                            onChange={(e) => setCardName(e.target.value)}
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                            {t.checkout.cardNumber}
                                        </label>
                                        <div className="relative">
                                            <Input
                                                type="text"
                                                required
                                                placeholder={t.checkout.cardNumberPlaceholder}
                                                value={cardNumber}
                                                onChange={handleCardNumberChange}
                                                className="font-mono tracking-wider"
                                            />
                                            <div className="absolute right-3 top-1/2 -translate-y-1/2 flex gap-1 text-xs font-mono text-text-tertiary">
                                                <span>VISA</span> • <span>MC</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                                {t.checkout.expiry}
                                            </label>
                                            <Input
                                                type="text"
                                                required
                                                placeholder={t.checkout.expiryPlaceholder}
                                                value={expiry}
                                                onChange={handleExpiryChange}
                                                className="font-mono text-center"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                                {t.checkout.cvc}
                                            </label>
                                            <Input
                                                type="password"
                                                required
                                                placeholder={t.checkout.cvcPlaceholder}
                                                value={cvc}
                                                onChange={handleCvcChange}
                                                className="font-mono text-center"
                                            />
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* PayPal Option */}
                            {paymentMethod === 'paypal' && (
                                <div className="p-6 rounded-xl bg-bg-secondary/60 border border-border-primary text-center space-y-4">
                                    <div className="text-3xl">🅿️</div>
                                    <p className="text-sm text-text-secondary">{t.checkout.paypalDesc}</p>
                                    <div className="inline-block px-4 py-2 rounded-lg bg-accent-blue/10 border border-accent-blue/30 text-accent-blue text-xs font-mono">
                                        🔒 Express Authorization Gateway
                                    </div>
                                </div>
                            )}

                            {/* Crypto Option */}
                            {paymentMethod === 'crypto' && (
                                <div className="p-6 rounded-xl bg-bg-secondary/60 border border-border-primary space-y-4">
                                    <p className="text-sm text-text-secondary">{t.checkout.cryptoDesc}</p>
                                    <div>
                                        <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                            {t.checkout.cryptoSelect}
                                        </label>
                                        <select
                                            value={cryptoCurrency}
                                            onChange={(e) => setCryptoCurrency(e.target.value)}
                                            className="w-full bg-bg-primary border border-border-primary rounded-xl px-4 py-2.5 text-sm text-text-primary focus:outline-none focus:border-accent-green"
                                        >
                                            <option value="USDT (BEP20)">USDT (Tether — BEP20 Binance Smart Chain)</option>
                                            <option value="USDT (TRC20)">USDT (Tether — TRC20 Tron Network)</option>
                                            <option value="BTC">Bitcoin (BTC Network)</option>
                                            <option value="ETH">Ethereum (ERC20 Network)</option>
                                        </select>
                                    </div>
                                    <div className="p-4 rounded-lg bg-bg-primary border border-accent-green/30 font-mono text-xs text-text-primary break-all">
                                        <span className="text-text-tertiary block mb-1">{t.checkout.cryptoAddress}:</span>
                                        0x71C...8A92B4e21F09A4D620023B0F8a9801C2
                                    </div>
                                </div>
                            )}

                            {/* Security SSL Guarantee Badge */}
                            <div className="mt-6 pt-4 border-t border-border-primary/50 flex items-center justify-center gap-2 text-xs text-text-tertiary font-mono">
                                <span>🔒</span>
                                <span>{t.checkout.sslNotice}</span>
                            </div>
                        </Card>

                        {/* Guarantee Card */}
                        <Card className="p-6 border border-accent-cyan/30 bg-gradient-to-r from-bg-card via-bg-card to-accent-cyan/5 flex items-start gap-4">
                            <div className="p-3 rounded-xl bg-accent-cyan/10 text-accent-cyan text-2xl flex-shrink-0">
                                🛡️
                            </div>
                            <div>
                                <h4 className="text-base font-heading font-bold text-text-primary mb-1">
                                    {t.checkout.guaranteeTitle}
                                </h4>
                                <p className="text-xs text-text-secondary leading-relaxed">
                                    {t.checkout.guaranteeDesc}
                                </p>
                            </div>
                        </Card>
                    </div>

                    {/* Right Column: Order Summary */}
                    <div className="lg:col-span-5 space-y-6">
                        <Card className="p-6 md:p-8 border-2 border-accent-green/40 bg-bg-card/95 shadow-xl">
                            <h2 className="text-lg font-heading font-bold text-text-primary pb-4 border-b border-border-primary mb-6">
                                {t.checkout.orderSummary}
                            </h2>

                            {/* Plan Selection Box */}
                            <div className="p-4 rounded-xl bg-bg-secondary border border-border-primary mb-6">
                                <div className="flex justify-between items-start mb-3">
                                    <div>
                                        <span className="text-xs font-mono text-accent-green uppercase tracking-wider block mb-0.5">
                                            {t.checkout.selectedPlan}
                                        </span>
                                        <h3 className="text-xl font-heading font-bold text-text-primary">
                                            {planDetails.title}
                                        </h3>
                                    </div>
                                    <div className="text-right">
                                        <span className="text-2xl font-mono font-bold text-text-primary">
                                            ${isAnnual ? planDetails.annualPrice : planDetails.monthlyPrice}
                                        </span>
                                        <span className="text-xs text-text-tertiary block">
                                            {isAnnual ? '/ year' : '/ month'}
                                        </span>
                                    </div>
                                </div>

                                {/* Billing Cycle Toggle */}
                                <div className="flex items-center justify-between pt-3 border-t border-border-primary/60 text-xs">
                                    <span className="text-text-secondary">{t.checkout.billingCycle}:</span>
                                    <button
                                        type="button"
                                        onClick={() => setIsAnnual(!isAnnual)}
                                        className="px-2.5 py-1 rounded bg-accent-green/10 text-accent-green font-bold hover:bg-accent-green/20 transition"
                                    >
                                        {isAnnual ? `${t.pricing.annual} (Save 20%)` : t.pricing.monthly}
                                    </button>
                                </div>
                            </div>

                            {/* Plan Features Preview */}
                            <div className="space-y-2 mb-6">
                                {planDetails.features.map((feat, idx) => (
                                    <div key={idx} className="flex items-center gap-2 text-xs text-text-secondary">
                                        <svg className="w-4 h-4 text-accent-green flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                        </svg>
                                        <span>{feat}</span>
                                    </div>
                                ))}
                            </div>

                            {/* Promo Code Box */}
                            <div className="mb-6">
                                <label className="block text-xs font-mono text-text-secondary mb-1.5">
                                    {t.checkout.promoCode}
                                </label>
                                <div className="flex gap-2">
                                    <Input
                                        type="text"
                                        placeholder={t.checkout.promoPlaceholder}
                                        value={promoInput}
                                        onChange={(e) => setPromoInput(e.target.value)}
                                        className="text-xs"
                                    />
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="sm"
                                        onClick={handleApplyPromo}
                                        className="px-4 text-xs flex-shrink-0"
                                    >
                                        {t.checkout.applyPromo}
                                    </Button>
                                </div>
                                {promoStatus === 'success' && (
                                    <p className="text-xs text-accent-green font-mono mt-1.5">{t.checkout.promoApplied}</p>
                                )}
                                {promoStatus === 'error' && (
                                    <p className="text-xs text-red-400 font-mono mt-1.5">{t.checkout.promoInvalid}</p>
                                )}
                            </div>

                            {/* Itemized Calculations */}
                            <div className="space-y-3 py-4 border-t border-b border-border-primary/60 font-mono text-sm mb-6">
                                <div className="flex justify-between text-text-secondary">
                                    <span>{t.checkout.subtotal}:</span>
                                    <span className="text-text-primary">${subtotal}.00</span>
                                </div>
                                {promoDiscount > 0 && (
                                    <div className="flex justify-between text-accent-green">
                                        <span>{t.checkout.discount} (20%):</span>
                                        <span>-${discountAmount}.00</span>
                                    </div>
                                )}
                                <div className="flex justify-between text-text-secondary">
                                    <span>{t.checkout.tax}:</span>
                                    <span>$0.00</span>
                                </div>
                                <div className="flex justify-between text-base font-bold text-text-primary pt-2 border-t border-border-primary/30">
                                    <span>{t.checkout.totalDue}:</span>
                                    <span className="text-xl text-accent-green font-mono">${totalDue}.00 USD</span>
                                </div>
                            </div>

                            {/* Submit Button */}
                            <Button
                                type="submit"
                                variant="primary"
                                size="lg"
                                disabled={isProcessing}
                                className="w-full justify-center shadow-lg shadow-accent-green/25 font-bold text-base py-4"
                            >
                                {isProcessing ? (
                                    <span className="flex items-center gap-2">
                                        <svg className="w-5 h-5 animate-spin text-bg-primary" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                        </svg>
                                        <span className="text-xs">{t.checkout.processing}</span>
                                    </span>
                                ) : (
                                    <span>{t.checkout.payNow} — ${totalDue}.00</span>
                                )}
                            </Button>
                        </Card>
                    </div>
                </form>
            </Container>
        </Layout>
    );
}
