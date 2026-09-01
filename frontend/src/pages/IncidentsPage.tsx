import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ThreatIncident } from '../types';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);

  useEffect(() => {
    api.getIncidents().then(setIncidents).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
        <h1 className="text-xl font-bold text-slate-900">Security Incident Triage Queue</h1>
        <p className="text-xs text-slate-500 mt-0.5">Real-time alerts, host containment actions, and forensic investigation timeline</p>
      </div>

      <div className="space-y-4">
        {incidents.map(inc => (
          <div key={inc.id} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
            <div className="flex justify-between items-start">
              <div>
                <span className="font-bold text-sm text-slate-900">{inc.title}</span>
                <p className="text-xs text-slate-500 font-mono mt-0.5">Host: {inc.affectedHost} • {inc.mitreTactic}</p>
              </div>
              <span className={`text-xs font-bold px-3 py-1 rounded-full ${
                inc.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'
              }`}>
                {inc.severity}
              </span>
            </div>
            <div className="pt-2 border-t border-slate-100 flex justify-between items-center text-xs text-slate-600">
              <span>Analyst: <strong>{inc.assignedAnalyst}</strong></span>
              <span className="font-mono">{inc.detectionTimestamp}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
