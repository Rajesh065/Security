export interface ThreatIncident {
  id: string;
  title: string;
  severity: string;
  category: string;
  mitreTactic: string;
  affectedHost: string;
  assignedAnalyst: string;
  status: string;
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
