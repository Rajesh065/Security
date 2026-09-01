import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ThreatIncident, SecurityMetric } from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Radio,
  Zap,
  ChevronRight,
  Server,
  Lock
} from 'lucide-react';

export const DashboardPage: React.FC<{ onNavigate: (t: string) => void }> = ({ onNavigate }) => {
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetric | null>(null);

  useEffect(() => {
    api.getIncidents().then(setIncidents).catch(() => {});
    api.getMetrics().then(setMetrics).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      {/* Welcome / Header Banner */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-red-700 bg-red-50 border border-red-200 px-2.5 py-0.5 rounded-md">
              CyberShield OS SOC Incident Response
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 mt-1.5">SOC Command Center & SIEM Triage</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Monitoring <strong className="text-slate-700 font-semibold">{metrics?.edrAgentsOnline || 4820} enterprise endpoints</strong> with real-time Sigma log correlation.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => onNavigate('incidents')}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white font-bold text-xs px-4 py-2.5 rounded-xl shadow-xs transition-all"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Investigate Incidents</span>
          </button>
          <button
            onClick={() => onNavigate('soar')}
            className="flex items-center gap-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs px-4 py-2.5 rounded-xl transition-all border border-slate-200"
          >
            <Zap className="w-4 h-4" />
            <span>SOAR Playbooks</span>
          </button>
        </div>
      </div>

      {/* Real-Time Telemetry Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div className="flex justify-between items-center text-xs font-bold text-slate-500">
            <span>ACTIVE INCIDENTS</span>
            <div className="p-2 bg-red-50 text-red-600 rounded-xl">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900 mt-2">{incidents.length || 3}</p>
          <div className="flex items-center gap-1.5 text-[11px] text-red-600 font-semibold mt-1">
            <span>1 Critical Cobalt Strike beacon</span>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div className="flex justify-between items-center text-xs font-bold text-slate-500">
            <span>MEAN TIME TO DETECT</span>
            <div className="p-2 bg-emerald-50 text-emerald-600 rounded-xl">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900 mt-2">14 Seconds</p>
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-600 font-semibold mt-1">
            <span>Mean time to contain: 48s</span>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div className="flex justify-between items-center text-xs font-bold text-slate-500">
            <span>EDR AGENTS ONLINE</span>
            <div className="p-2 bg-blue-50 text-blue-600 rounded-xl">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900 mt-2">4,820</p>
          <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium mt-1">
            <span>Linux, Windows & macOS fleet</span>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div className="flex justify-between items-center text-xs font-bold text-slate-500">
            <span>DAILY THREAT LOGS</span>
            <div className="p-2 bg-purple-50 text-purple-600 rounded-xl">
              <Radio className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-900 mt-2">184.5M</p>
          <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium mt-1">
            <span>100% Sigma rules evaluated</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Active Security Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
          <div className="flex justify-between items-center border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Active High-Priority Threat Incidents</h2>
              <p className="text-[11px] text-slate-500">Real-time triage, affected host isolation, and MITRE mapping</p>
            </div>
            <button
              onClick={() => onNavigate('incidents')}
              className="text-red-700 hover:text-red-800 text-xs font-bold flex items-center gap-1"
            >
              <span>View Queue</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-100">
            {incidents.map(inc => (
              <div key={inc.id} className="py-3.5 flex items-center justify-between gap-4 hover:bg-slate-50/80 px-2 rounded-xl transition-all">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-slate-900">{inc.title}</span>
                    <span className="text-[10px] font-mono bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded">{inc.id}</span>
                  </div>
                  <p className="text-xs text-slate-500">{inc.affectedHost} • {inc.mitreTactic}</p>
                  <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                    <span>{inc.assignedAnalyst}</span>
                    <span>•</span>
                    <span>{inc.sigmaRuleId}</span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full ${
                    inc.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'
                  }`}>
                    {inc.severity}
                  </span>

                  <button
                    onClick={() => api.quarantineHost(inc.id)}
                    className="bg-red-50 text-red-700 hover:bg-red-100 text-xs font-bold px-3 py-1.5 rounded-lg transition-all"
                  >
                    Quarantine
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right 1 Col: MITRE Heatmap Highlights */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">MITRE ATT&CK Matrix</h2>
            <p className="text-[11px] text-slate-500">Enterprise Tactics Coverage</p>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl flex justify-between items-center text-red-900">
              <span className="font-bold">Command and Control (TA0011)</span>
              <span className="text-[10px] font-bold bg-red-200 px-2 py-0.5 rounded">1 Active</span>
            </div>
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl flex justify-between items-center text-amber-900">
              <span className="font-bold">Credential Access (TA0006)</span>
              <span className="text-[10px] font-bold bg-amber-200 px-2 py-0.5 rounded">1 Active</span>
            </div>
            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl flex justify-between items-center text-emerald-900">
              <span className="font-bold">Exfiltration (TA0010)</span>
              <span className="text-[10px] font-bold bg-emerald-200 px-2 py-0.5 rounded">Remediated</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
