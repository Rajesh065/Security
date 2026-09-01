export type UserRole = 'ADMIN' | 'SOC_ANALYST_L3' | 'INCIDENT_COMMANDER' | 'THREAT_HUNTER';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  team: string;
  accessTier: string;
  createdAt: string;
}

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ThreatIncident {
  id: string;
  title: string;
  severity: ThreatSeverity;
  category: string;
  mitreTactic: string;
  affectedHost: string;
  assignedAnalyst: string;
  status: 'OPEN_INVESTIGATING' | 'CONTAINMENT_IN_PROGRESS' | 'REMEDIATED_CLOSED';
  detectionTimestamp: string;
  sigmaRuleId: string;
}

export interface SecurityMetric {
  activeIncidentsCount: number;
  criticalAlertsCount: number;
  edrAgentsOnline: number;
  meanTimeToDetectSec: number;
  meanTimeToContainSec: number;
  threatEventsProcessedToday: number;
}
