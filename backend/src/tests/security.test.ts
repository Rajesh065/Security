import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../app';

describe('CyberShield SOC API & SIEM Engine', () => {
  it('should return system health and active EDR fleet', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
  });

  it('should list security incidents', async () => {
    const res = await request(app).get('/api/v1/incidents');
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
  });

  it('should execute SOAR endpoint quarantine action', async () => {
    const res = await request(app).post('/api/v1/incidents/INC-2026-8891/quarantine');
    expect(res.status).toBe(200);
    expect(res.body.data.success).toBe(true);
  });
});
