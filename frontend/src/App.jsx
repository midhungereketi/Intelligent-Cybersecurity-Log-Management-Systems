import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import LoginView from './components/LoginView';
import DashboardView from './components/DashboardView';
import LogsView from './components/LogsView';
import AlertsView from './components/AlertsView';
import IncidentsView from './components/IncidentsView';
import DetectionView from './components/DetectionView';
import AdminView from './components/AdminView';
import { api, getStoredToken, getStoredUser, setStoredToken, setStoredUser } from './api';

export default function App() {
  const [currentUser, setCurrentUser] = useState(getStoredUser());
  const [activeTab, setActiveTab] = useState('dashboard');
  const [authChecking, setAuthChecking] = useState(true);
  const [prefillAlertForIncident, setPrefillAlertForIncident] = useState(null);

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

  const handleLogout = async () => {
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
  };

  const handlePromoteAlertToIncident = (alert) => {
    setPrefillAlertForIncident(alert);
    setActiveTab('incidents');
  };

  if (authChecking) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-main)', color: 'var(--cyan-glow)' }}>
        Initializing CyberShield SOC...
      </div>
    );
  }

  if (!currentUser) {
    return <LoginView onLoginSuccess={(user) => setCurrentUser(user)} />;
  }

  return (
    <div className="app-container">
      <Sidebar 
        activeTab={activeTab} 
        onSelectTab={setActiveTab} 
        currentUser={currentUser} 
      />

      <div className="main-content">
        <Navbar 
          currentUser={currentUser} 
          onLogout={handleLogout} 
          activeTab={activeTab}
        />

        <main className="page-body">
          {activeTab === 'dashboard' && (
            <DashboardView onNavigate={(tab) => setActiveTab(tab)} />
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
        </main>
      </div>
    </div>
  );
}
