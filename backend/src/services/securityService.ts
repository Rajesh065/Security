import { mockDataStore } from '../models/mockData';
import { ThreatIncident, SecurityMetric } from '../models/types';

export class SecurityService {
  static getIncidents(): ThreatIncident[] { return mockDataStore.incidents; }
  static getIncidentById(id: string): ThreatIncident | undefined { return mockDataStore.incidents.find(i => i.id === id); }
  static getMetrics(): SecurityMetric { return mockDataStore.metrics; }
  static quarantineHost(incidentId: string) {
    const inc = mockDataStore.incidents.find(i => i.id === incidentId);
    if (!inc) return null;
    inc.status = 'CONTAINMENT_IN_PROGRESS';
    return { success: true, incidentId, host: inc.affectedHost, action: 'SOAR_EDR_NETWORK_ISOLATION_APPLIED', timestamp: new Date().toISOString() };
  }
}
