import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Crosshair,
  Terminal,
  Zap,
  Cloud
} from 'lucide-react';

export const HorizontalNav: React.FC<{ currentTab: string; setCurrentTab: (t: string) => void }> = ({ currentTab, setCurrentTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Command Center', icon: LayoutDashboard, badge: 'Live' },
    { id: 'incidents', label: 'Incident Triage Queue', icon: ShieldAlert, badge: '3' },
    { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: Crosshair },
    { id: 'cve', label: 'CVE Vulnerability Feeds', icon: Terminal },
    { id: 'soar', label: 'Automated SOAR Playbooks', icon: Zap },
    { id: 'cspm', label: 'Cloud Posture & K8s Hardening', icon: Cloud }
  ];

  return (
    <nav className="bg-white border-b border-slate-200 px-6 overflow-x-auto shadow-xs sticky top-[57px] z-30">
      <div className="flex items-center gap-1.5 min-w-max py-2 max-w-7xl mx-auto">
        {navItems.map(item => {
          const Icon = item.icon;
          const active = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
                active
                  ? 'bg-red-50 text-red-800 font-bold border border-red-200/80 shadow-xs'
                  : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${active ? 'text-red-700' : 'text-slate-400'}`} />
              <span>{item.label}</span>
              {item.badge && (
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                  active ? 'bg-red-200 text-red-900' : 'bg-slate-100 text-slate-600'
                }`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
