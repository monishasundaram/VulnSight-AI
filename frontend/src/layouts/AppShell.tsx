import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { Activity, BookOpenText, Bug, ChevronDown, FileBarChart2, LayoutDashboard, Menu, Search, Settings2, ShieldCheck, Target, X } from 'lucide-react';
import { useAuth } from '../services/auth';
import { apiRequest } from '../services/api';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/scan/new', label: 'New Scan', icon: Activity },
  { to: '/scans', label: 'Scan History', icon: FileBarChart2 },
  { to: '/findings', label: 'Vulnerabilities', icon: Bug },
  { to: '/targets', label: 'Targets', icon: Target },
  { to: '/reports', label: 'Reports', icon: FileBarChart2 },
];

export default function AppShell() {
  const [open, setOpen] = useState(false);
  const { user, logout, error } = useAuth();
  useEffect(() => {
    const controller = new AbortController();
    if (!user) {
      document.documentElement.dataset.theme = 'dark';
      return () => controller.abort();
    }
    apiRequest<{ preferences: { theme?: string } }>('/api/settings', { signal: controller.signal })
      .then((response) => { document.documentElement.dataset.theme = response.preferences.theme === 'light' ? 'light' : 'dark'; })
      .catch(() => { /* Settings errors are surfaced on the Settings page; keep the default theme. */ });
    return () => controller.abort();
  }, [user?.id]);
  return (
    <div className="app-frame">
      <aside className={`sidebar ${open ? 'sidebar-open' : ''}`} aria-label="Main navigation">
        <NavLink className="brand" to="/" onClick={() => setOpen(false)}>
          <span className="brand-mark" aria-hidden="true"><ShieldCheck size={18} strokeWidth={2.2} /></span>
          <span className="brand-copy"><b>VulnSight</b><small>AI SECURITY WORKSPACE</small></span>
          <button className="icon-button mobile-close" aria-label="Close navigation" onClick={(event) => { event.preventDefault(); setOpen(false); }}><X size={17} /></button>
        </NavLink>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="side-links">
          {navItems.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{label === 'New Scan' && <span className="nav-plus">+</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-spacer" />
        <div className="scope-card">
          <span className="scope-dot" />
          <div><b>Authorized scope only</b><small>Assess assets you control.</small></div>
        </div>
        <nav className="side-links side-links-bottom">
          <NavLink to="/settings" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={() => setOpen(false)}><Settings2 size={17} /><span>Settings</span></NavLink>
          <NavLink to="/help" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={() => setOpen(false)}><BookOpenText size={17} /><span>Help & Documentation</span></NavLink>
        </nav>
        <div className="sidebar-foot"><span className="status-pip" />Local workspace <span className="foot-version">v1.0</span></div>
      </aside>
      {open && <button className="sidebar-scrim" aria-label="Close navigation overlay" onClick={() => setOpen(false)} />}
      <section className="main-column">
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={19} /></button>
          <div className="breadcrumb"><span>VulnSight AI</span><span className="crumb-slash">/</span><strong>Security workspace</strong></div>
          <div className="topbar-actions">
            <NavLink className="global-search" to="/scans" aria-label="Open searchable scan history"><Search size={15} /><span>Search scan history</span><kbd>Open</kbd></NavLink>
            <div className="profile-menu"><NavLink to="/settings" className="profile-button" aria-label="Open profile and settings"><span className="avatar">{user?.email.slice(0, 2).toUpperCase() || 'VS'}</span><span className="profile-label">{user?.email || 'Workspace'}</span><ChevronDown size={14} /></NavLink><button type="button" className="logout-button" onClick={() => void logout()}>Sign out</button></div>
          </div>
        </header>
        {error && <div className="shell-alert" role="alert">{error}</div>}
        <main className="page-content"><Outlet /></main>
        <footer className="app-footer"><span>VulnSight AI · Authorized assessments only</span><span>Evidence-led · Non-destructive by default</span></footer>
      </section>
    </div>
  );
}
