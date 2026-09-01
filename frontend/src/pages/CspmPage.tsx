import React from 'react';
import { Cloud, CheckCircle2 } from 'lucide-react';

export const CspmPage: React.FC = () => (
  <div className="space-y-6">
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
      <h1 className="text-xl font-bold text-slate-900">Cloud Security Posture Management (CSPM) & K8s Hardening</h1>
      <p className="text-xs text-slate-500 mt-0.5">AWS S3 public access guards, Azure NSG rules, and CIS Docker/Kubernetes benchmark auditors</p>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
        <p className="text-xs font-bold text-slate-400 uppercase font-mono">AWS S3 HARDENING</p>
        <p className="text-2xl font-bold text-emerald-600">100% Compliant</p>
        <p className="text-xs text-slate-500">All buckets private with KMS-SSE</p>
      </div>
      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
        <p className="text-xs font-bold text-slate-400 uppercase font-mono">KUBERNETES PODS</p>
        <p className="text-2xl font-bold text-slate-900">340 / 340 Pods</p>
        <p className="text-xs text-slate-500">Non-root read-only root filesystems</p>
      </div>
      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2">
        <p className="text-xs font-bold text-slate-400 uppercase font-mono">IAM LEAST PRIVILEGE</p>
        <p className="text-2xl font-bold text-emerald-600">0 Wildcard Roles</p>
        <p className="text-xs text-slate-500">Zero AdministratorAccess grants</p>
      </div>
    </div>
  </div>
);
