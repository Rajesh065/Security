import React from 'react';
import { Terminal } from 'lucide-react';

export const CvePage: React.FC = () => (
  <div className="space-y-6">
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
      <h1 className="text-xl font-bold text-slate-900">CVE Vulnerability & Exploit Feed</h1>
      <p className="text-xs text-slate-500 mt-0.5">NVD vulnerability database, CVSS 3.1 severity scores, and OWASP Top 10 threat signatures</p>
    </div>

    <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
      <p className="text-xs font-bold text-slate-800">CVE-2026-20001: Remote Code Execution in Apache Ingress Controller</p>
      <p className="text-xs text-slate-500">CVSS 9.8 Critical • Exploit Signature: Active in Wild • Automated virtual patch applied via eBPF</p>
    </div>
  </div>
);
