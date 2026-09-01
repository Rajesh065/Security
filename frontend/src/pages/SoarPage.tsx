import React from 'react';
import { Zap, Play } from 'lucide-react';

export const SoarPage: React.FC = () => (
  <div className="space-y-6">
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex justify-between items-center">
      <div>
        <h1 className="text-xl font-bold text-slate-900">Automated SOAR Incident Containment Playbooks</h1>
        <p className="text-xs text-slate-500 mt-0.5">Automated host network quarantine, brute force IP bans, and IAM credential revocation</p>
      </div>
      <button className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs px-4 py-2.5 rounded-xl shadow-xs flex items-center gap-1.5 transition-all">
        <Play className="w-4 h-4 fill-white" />
        <span>Run Containment Playbook</span>
      </button>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
        <span className="text-xs font-bold text-slate-900">Ransomware Host Network Isolation</span>
        <p className="text-xs text-slate-500">Instantly isolates endpoint network adapter while preserving forensic memory telemetry.</p>
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">Avg Execution: 5s</span>
      </div>
      <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
        <span className="text-xs font-bold text-slate-900">Brute Force IP Edge Ban</span>
        <p className="text-xs text-slate-500">Pushes dynamic firewall block rules to Cloudflare / Palo Alto Edge firewalls.</p>
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">Avg Execution: 100ms</span>
      </div>
    </div>
  </div>
);
