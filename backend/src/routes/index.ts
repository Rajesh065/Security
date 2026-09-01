import { Router } from 'express';
import { SecurityController } from '../controllers/securityController';

const router = Router();
router.get('/incidents', SecurityController.getIncidents);
router.get('/incidents/:id', SecurityController.getIncidentById);
router.get('/metrics', SecurityController.getMetrics);
router.post('/incidents/:id/quarantine', SecurityController.quarantineHost);

export default router;
