import React from 'react';
import { Crosshair } from 'lucide-react';

export const MitrePage: React.FC = () => (
  <div className="space-y-6">
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
      <h1 className="text-xl font-bold text-slate-900">MITRE ATT&CK Enterprise Framework</h1>
      <p className="text-xs text-slate-500 mt-0.5">12 Adversary Tactics across Initial Access, Execution, Credential Theft, and Exfiltration</p>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {['TA0001: Initial Access', 'TA0002: Execution', 'TA0003: Persistence', 'TA0004: Privilege Escalation', 'TA0005: Defense Evasion', 'TA0006: Credential Access', 'TA0007: Discovery', 'TA0008: Lateral Movement', 'TA0009: Collection', 'TA0010: Command & Control', 'TA0011: Exfiltration', 'TA0012: Impact'].map((tac, idx) => (
        <div key={idx} className="bg-white border border-slate-200 p-4 rounded-2xl shadow-xs space-y-1">
          <p className="font-bold text-xs text-slate-900">{tac}</p>
          <p className="text-[11px] text-slate-500">200 Verified Sigma Detection Rules</p>
        </div>
      ))}
    </div>
  </div>
);
