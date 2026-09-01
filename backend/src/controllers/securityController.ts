import { Request, Response } from 'express';
import { SecurityService } from '../services/securityService';

export class SecurityController {
  static getIncidents(req: Request, res: Response): void { res.json({ success: true, data: SecurityService.getIncidents() }); }
  static getIncidentById(req: Request, res: Response): void {
    const incident = SecurityService.getIncidentById(req.params.id);
    if (!incident) { res.status(404).json({ success: false, message: 'Incident not found' }); return; }
    res.json({ success: true, data: incident });
  }
  static getMetrics(req: Request, res: Response): void { res.json({ success: true, data: SecurityService.getMetrics() }); }
  static quarantineHost(req: Request, res: Response): void {
    const result = SecurityService.quarantineHost(req.params.id);
    if (!result) { res.status(404).json({ success: false, message: 'Incident not found' }); return; }
    res.json({ success: true, data: result });
  }
}
