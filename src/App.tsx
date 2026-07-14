import {
    lazy, Suspense, Component,
    type ErrorInfo, type ReactNode, type ComponentType,
} from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/contexts/AuthContext';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { LanguageProvider } from '@/contexts/LanguageContext';
import ProtectedRoute from '@components/ProtectedRoute';
 
// ── Page chunks — each is downloaded only when the user navigates to it ──────
const Home             = lazy(() => import('@pages/Home'));
const Login            = lazy(() => import('@pages/Login'));
const Register         = lazy(() => import('@pages/Register'));
const ForgotPassword   = lazy(() => import('@pages/ForgotPassword'));
const ResetPassword    = lazy(() => import('@pages/ResetPassword'));
const Dashboard        = lazy(() => import('@pages/Dashboard'));
const ScanWebsite      = lazy(() => import('@pages/ScanWebsite'));
const ScanResults      = lazy(() => import('@pages/ScanResults'));
const ScanHistory      = lazy(() => import('@pages/ScanHistory'));
const Learn            = lazy(() => import('@pages/Learn'));
const ArticleDetail    = lazy(() => import('@pages/ArticleDetail'));
const Documentation    = lazy(() => import('@pages/Documentation'));
const Pricing          = lazy(() => import('@pages/Pricing'));
const Checkout         = lazy(() => import('@pages/Checkout'));
const About            = lazy(() => import('@pages/About'));
const Contact          = lazy(() => import('@pages/Contact'));
const Services         = lazy(() => import('@pages/Services'));
const Profile          = lazy(() => import('@pages/Profile'));
const Terms            = lazy(() => import('@pages/Terms'));
const Privacy          = lazy(() => import('@pages/Privacy'));
const CookiePolicy     = lazy(() => import('@pages/CookiePolicy'));
const Compliance       = lazy(() => import('@pages/Compliance'));
const Careers          = lazy(() => import('@pages/Careers'));
const Partners         = lazy(() => import('@pages/Partners'));
const ScheduledScans   = lazy(() => import('@pages/ScheduledScans'));
const ScopeManagement  = lazy(() => import('@pages/ScopeManagement'));
const Targets          = lazy(() => import('@pages/Targets'));
const AssetInventory   = lazy(() => import('@pages/AssetInventory'));
const WebhookSettings  = lazy(() => import('@pages/WebhookSettings'));
const ScanComparison   = lazy(() => import('@pages/ScanComparison'));
const Onboarding       = lazy(() => import('@pages/Onboarding'));
const NotFound         = lazy(() => import('@pages/NotFound'));

// Admin pages — grouped into a separate chunk by Vite's manualChunks
const AdminDashboard    = lazy(() => import('@pages/admin/AdminDashboard'));
const AdminUsers        = lazy(() => import('@pages/admin/AdminUsers'));
const AdminML           = lazy(() => import('@pages/admin/AdminML'));
const AdminScans        = lazy(() => import('@pages/admin/AdminScans'));
const AdminSettings     = lazy(() => import('@pages/admin/AdminSettings'));
const AdminContacts     = lazy(() => import('@pages/admin/AdminContacts'));
const AdminApplications = lazy(() => import('@pages/admin/AdminApplications'));

// ChatbotWidget gets its own Suspense so it never blocks page rendering
const ChatbotWidget = lazy(() => import('@components/layout/ChatbotWidget'));

// ── Error boundary: surfaces load/render crashes instead of blank screen ──────
class AppErrorBoundary extends Component<
    { children: ReactNode },
    { error: Error | null }
> {
    state = { error: null as Error | null };
    static getDerivedStateFromError(e: Error) { return { error: e }; }
    componentDidCatch(e: Error, info: ErrorInfo) {
        console.error('[AppErrorBoundary]', e, info);
    }
    render() {
        if (this.state.error) {
            return (
                <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center gap-4 p-8 text-white">
                    <h1 className="text-2xl font-bold text-red-400">Something went wrong</h1>
                    <pre className="text-sm text-gray-400 max-w-xl whitespace-pre-wrap">
                        {this.state.error.message}
                    </pre>
                    <button
                        onClick={() => window.location.reload()}
                        className="px-4 py-2 bg-cyan-600 rounded-lg hover:bg-cyan-500"
                    >
                        Reload
                    </button>
                </div>
            );
        }
        return this.props.children;
    }
}

const PageLoader = () => (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
    </div>
);

// L wraps each lazy page in its own ErrorBoundary + Suspense so a single
// failing chunk never crashes the whole app or produces a blank screen.
// ComponentType<object> accepts any valid React component regardless of
// how it is typed (FC, function, class, () => ReactElement | null, etc.).
function L({ C }: { C: React.LazyExoticComponent<ComponentType<object>> }) {
    return (
        <AppErrorBoundary>
            <Suspense fallback={<PageLoader />}><C /></Suspense>
        </AppErrorBoundary>
    );
}

function App() {
    return (
        <ThemeProvider>
            <LanguageProvider>
                <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
                    <AuthProvider>
                        <Routes>
                            <Route path="/" element={<L C={Home} />} />
                            <Route path="/login" element={<L C={Login} />} />
                            <Route path="/register" element={<L C={Register} />} />
                            <Route path="/forgot-password" element={<L C={ForgotPassword} />} />
                            <Route path="/reset-password" element={<L C={ResetPassword} />} />
                            <Route path="/dashboard" element={<ProtectedRoute><L C={Dashboard} /></ProtectedRoute>} />
                            <Route path="/scan" element={<ProtectedRoute><L C={ScanWebsite} /></ProtectedRoute>} />
                            <Route path="/scan/results/:id" element={<ProtectedRoute><L C={ScanResults} /></ProtectedRoute>} />
                            <Route path="/history" element={<ProtectedRoute><L C={ScanHistory} /></ProtectedRoute>} />
                            <Route path="/learn" element={<L C={Learn} />} />
                            <Route path="/learn/:slug" element={<L C={ArticleDetail} />} />
                            <Route path="/docs" element={<L C={Documentation} />} />
                            <Route path="/pricing" element={<L C={Pricing} />} />
                            <Route path="/checkout" element={<L C={Checkout} />} />
                            <Route path="/about" element={<L C={About} />} />
                            <Route path="/contact" element={<L C={Contact} />} />
                            <Route path="/services" element={<L C={Services} />} />
                            <Route path="/profile" element={<ProtectedRoute><L C={Profile} /></ProtectedRoute>} />
                            <Route path="/terms" element={<L C={Terms} />} />
                            <Route path="/privacy" element={<L C={Privacy} />} />
                            <Route path="/cookies" element={<L C={CookiePolicy} />} />
                            <Route path="/compliance" element={<L C={Compliance} />} />
                            <Route path="/careers" element={<L C={Careers} />} />
                            <Route path="/partners" element={<L C={Partners} />} />
                            <Route path="/scheduled-scans" element={<ProtectedRoute><L C={ScheduledScans} /></ProtectedRoute>} />
                            <Route path="/scopes" element={<ProtectedRoute><L C={ScopeManagement} /></ProtectedRoute>} />
                            <Route path="/targets" element={<ProtectedRoute><L C={Targets} /></ProtectedRoute>} />
                            <Route path="/assets" element={<ProtectedRoute><L C={AssetInventory} /></ProtectedRoute>} />
                            <Route path="/settings/webhooks" element={<ProtectedRoute><L C={WebhookSettings} /></ProtectedRoute>} />
                            <Route path="/scan/compare/:id1/:id2" element={<ProtectedRoute><L C={ScanComparison} /></ProtectedRoute>} />
                            <Route path="/onboarding" element={<ProtectedRoute><L C={Onboarding} /></ProtectedRoute>} />

                            {/* Admin Routes */}
                            <Route path="/admin" element={<ProtectedRoute adminOnly><L C={AdminDashboard} /></ProtectedRoute>} />
                            <Route path="/admin/users" element={<ProtectedRoute adminOnly><L C={AdminUsers} /></ProtectedRoute>} />
                            <Route path="/admin/scans" element={<ProtectedRoute adminOnly><L C={AdminScans} /></ProtectedRoute>} />
                            <Route path="/admin/ml" element={<ProtectedRoute adminOnly><L C={AdminML} /></ProtectedRoute>} />
                            <Route path="/admin/settings" element={<ProtectedRoute adminOnly><L C={AdminSettings} /></ProtectedRoute>} />
                            <Route path="/admin/contacts" element={<ProtectedRoute adminOnly><L C={AdminContacts} /></ProtectedRoute>} />
                            <Route path="/admin/applications" element={<ProtectedRoute adminOnly><L C={AdminApplications} /></ProtectedRoute>} />

                            {/* Catch-all 404 */}
                            <Route path="*" element={<L C={NotFound} />} />
                        </Routes>

                        {/* ChatbotWidget loads silently in the background */}
                        <Suspense fallback={null}>
                            <ChatbotWidget />
                        </Suspense>
                    </AuthProvider>
                </Router>
            </LanguageProvider>
        </ThemeProvider>
    );
}

export default App;
