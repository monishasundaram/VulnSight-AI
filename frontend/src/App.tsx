import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import AppShell from './layouts/AppShell';
import { AuthProvider } from './services/auth';
import { ProtectedRoute, PublicOnlyRoute } from './components/RouteGuards';

const Overview = lazy(() => import('./pages/Overview'));
const AuthPage = lazy(() => import('./pages/AuthPage'));
const Targets = lazy(() => import('./pages/Targets'));
const ScanWizard = lazy(() => import('./pages/ScanWizard'));
const ScanProgress = lazy(() => import('./pages/ScanProgress'));
const ScanHistory = lazy(() => import('./pages/ScanHistory'));
const Findings = lazy(() => import('./pages/Findings'));
const FindingDetails = lazy(() => import('./pages/FindingDetails'));
const Reports = lazy(() => import('./pages/Reports'));
const Settings = lazy(() => import('./pages/Settings'));
const Help = lazy(() => import('./pages/Help'));

function RouteLoading() {
  return <main className="route-loading" role="status"><span className="loading-dot" /> Loading VulnSight workspace…</main>;
}

export default function App() {
  return <AuthProvider>
    <Suspense fallback={<RouteLoading />}>
      <Routes>
        <Route element={<PublicOnlyRoute />}>
          <Route path="/login" element={<AuthPage mode="login" />} />
          <Route path="/register" element={<AuthPage mode="register" />} />
        </Route>
        <Route element={<ProtectedRoute />}>
          <Route element={<AppShell />}>
            <Route path="/" element={<Overview />} />
            <Route path="/scan/new" element={<ScanWizard />} />
            <Route path="/scans" element={<ScanHistory />} />
            <Route path="/scans/:scanId" element={<ScanProgress />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:findingId" element={<FindingDetails />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:scanId" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/help" element={<Help />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  </AuthProvider>;
}
