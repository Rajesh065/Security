import React, { useState } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { HorizontalNav } from './components/HorizontalNav';
import { DashboardPage } from './pages/DashboardPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { MitrePage } from './pages/MitrePage';
import { CvePage } from './pages/CvePage';
import { SoarPage } from './pages/SoarPage';
import { CspmPage } from './pages/CspmPage';

export function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');

  return (
    <AuthProvider>
      <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-['Plus_Jakarta_Sans',sans-serif]">
        <Navbar onNewIncident={() => setCurrentTab('incidents')} />
        <HorizontalNav currentTab={currentTab} setCurrentTab={setCurrentTab} />
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
          {currentTab === 'dashboard' && <DashboardPage onNavigate={setCurrentTab} />}
          {currentTab === 'incidents' && <IncidentsPage />}
          {currentTab === 'mitre' && <MitrePage />}
          {currentTab === 'cve' && <CvePage />}
          {currentTab === 'soar' && <SoarPage />}
          {currentTab === 'cspm' && <CspmPage />}
        </main>
      </div>
    </AuthProvider>
  );
}

export default App;
