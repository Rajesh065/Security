import { User, ThreatIncident, SecurityMetric } from './types';

export const mockDataStore: {
  users: User[];
  incidents: ThreatIncident[];
  metrics: SecurityMetric;
} = {
  users: [
    { id: 'usr-sec-1', name: 'Viktor Vance', email: 'viktor.vance@cybershield.enterprise', role: 'INCIDENT_COMMANDER', team: 'Global Cyber Incident Response', accessTier: 'TIER_1_SECURITY_LEAD', createdAt: '2025-01-10T08:00:00.000Z' },
    { id: 'usr-sec-2', name: 'Clara Mercer', email: 'clara.mercer@cybershield.enterprise', role: 'THREAT_HUNTER', team: 'Adversary Tactics & Sigma Intel', accessTier: 'THREAT_ANALYST_PRO', createdAt: '2025-01-15T09:00:00.000Z' }
  ],

  incidents: [
    {
      id: 'INC-2026-8891',
      title: 'Suspicious PowerShell Encoded Base64 Execution with Cobalt Strike Beaconing',
      severity: 'CRITICAL',
      category: 'Command and Control / Execution',
      mitreTactic: 'TA0011 (Command and Control) / T1059.001',
      affectedHost: 'finance-prod-db-node-04.corp.internal',
      assignedAnalyst: 'Viktor Vance (Lead Commander)',
      status: 'OPEN_INVESTIGATING',
      detectionTimestamp: '2026-08-31T22:15:00.000Z',
      sigmaRuleId: 'SIG-WIN-POWERSHELL-ENCODED-001'
    },
    {
      id: 'INC-2026-8892',
      title: 'Active Brute-Force SSH Inbound Attack on Bastion Gateway',
      severity: 'HIGH',
      category: 'Credential Access',
      mitreTactic: 'TA0006 (Credential Access) / T1110.001',
      affectedHost: 'bastion-eu-west-ingress.dmz.internal',
      assignedAnalyst: 'Clara Mercer (Threat Hunter)',
      status: 'CONTAINMENT_IN_PROGRESS',
      detectionTimestamp: '2026-08-31T22:30:00.000Z',
      sigmaRuleId: 'SIG-NET-SSH-BRUTEFORCE-004'
    },
    {
      id: 'INC-2026-8893',
      title: 'Unrestricted Public Read Access Detected on S3 Customer PII Bucket',
      severity: 'HIGH',
      category: 'Cloud Misconfiguration / Data Exposure',
      mitreTactic: 'TA0010 (Exfiltration) / T1530',
      affectedHost: 'aws-s3://enterprise-customer-pii-lakehouse',
      assignedAnalyst: 'Viktor Vance (Lead Commander)',
      status: 'REMEDIATED_CLOSED',
      detectionTimestamp: '2026-08-31T21:40:00.000Z',
      sigmaRuleId: 'SIG-CLOUD-AWS-S3-PUBLIC-002'
    }
  ],

  metrics: {
    activeIncidentsCount: 3,
    criticalAlertsCount: 1,
    edrAgentsOnline: 4820,
    meanTimeToDetectSec: 14,
    meanTimeToContainSec: 48,
    threatEventsProcessedToday: 184500000
  }
};
