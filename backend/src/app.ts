import express from 'express';
import cors from 'cors';
import routes from './routes';

export const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', system: 'CyberShield OS Enterprise SOC Engine', edrAgents: 4820, activeIncidents: 3, version: '1.0.0' });
});

app.use('/api/v1', routes);
