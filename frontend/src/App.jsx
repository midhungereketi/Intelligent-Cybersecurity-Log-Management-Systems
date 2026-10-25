import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import LoginView from './components/LoginView';
import DashboardView from './components/DashboardView';
import LogsView from './components/LogsView';
import AlertsView from './components/AlertsView';
import IncidentsView from './components/IncidentsView';
import DetectionView from './components/DetectionView';
import AdminView from './components/AdminView';
import Backdrop from './components/fx/Backdrop';
import BootScreen from './components/fx/BootScreen';
import CommandPalette from './components/fx/CommandPalette';
import usePointerEffects from './components/fx/usePointerEffects';
import { getNavItems } from './navigation';
import { api, getStoredToken, getStoredUser, setStoredToken, setStoredUser } from './api';

export default function App() {
  const [currentUser, setCurrentUser] = useState(getStoredUser());
  const [activeTab, setActiveTab] = useState('dashboard');
  const [authChecking, setAuthChecking] = useState(true);
  const [prefillAlertForIncident, setPrefillAlertForIncident] = useState(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  usePointerEffects();

  // Check existing session
  useEffect(() => {
    const verifySession = async () => {
      const token = getStoredToken();
      if (!token) {
        setAuthChecking(false);
        return;
      }
      try {
        const me = await api.getMe();
        setCurrentUser(me);
        setStoredUser(me);
      } catch {
        setStoredToken(null);
        setStoredUser(null);
        setCurrentUser(null);
      } finally {
        setAuthChecking(false);
      }
    };

    verifySession();

    const handleUnauthorized = () => {
      setCurrentUser(null);
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  // Ctrl/Cmd+K toggles the command palette while signed in
  useEffect(() => {
    const onKey = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        if (currentUser) setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [currentUser]);

  const handleLogout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Ignore
    } finally {
      setStoredToken(null);
      setStoredUser(null);
      setCurrentUser(null);
      setActiveTab('dashboard');
    }
  }, []);

  const handlePromoteAlertToIncident = (alert) => {
    setPrefillAlertForIncident(alert);
    setActiveTab('incidents');
  };

  const selectTab = useCallback((tab) => {
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  if (authChecking) {
    return <BootScreen />;
  }

  if (!currentUser) {
    return (
      <>
        <Backdrop />
        <div className="cursor-glow" />
        <LoginView onLoginSuccess={(user) => setCurrentUser(user)} />
      </>
    );
  }

  const navItems = getNavItems(currentUser);

  return (
    <>
      <Backdrop />
      <div className="cursor-glow" />
      <div className="app-container">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={selectTab}
          navItems={navItems}
        />

        <div className="main-content">
          <Navbar
            currentUser={currentUser}
            onLogout={handleLogout}
            activeTab={activeTab}
            navItems={navItems}
            onOpenPalette={() => setPaletteOpen(true)}
          />

          <main className="page-body">
            <div key={activeTab} className="page-transition">
              {activeTab === 'dashboard' && (
                <DashboardView onNavigate={selectTab} />
              )}

              {activeTab === 'logs' && (
                <LogsView />
              )}

              {activeTab === 'alerts' && (
                <AlertsView onPromoteToIncident={handlePromoteAlertToIncident} />
              )}

              {activeTab === 'incidents' && (
                <IncidentsView
                  prefillAlert={prefillAlertForIncident}
                  onClearPrefill={() => setPrefillAlertForIncident(null)}
                />
              )}

              {activeTab === 'detection' && (
                <DetectionView />
              )}

              {activeTab === 'admin' && currentUser.role_name === 'ADMIN' && (
                <AdminView />
              )}
            </div>
          </main>
        </div>
      </div>
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        items={navItems}
        onSelect={selectTab}
        onLogout={handleLogout}
      />
    </>
  );
}
