import { app } from './app';
import { config } from './config';
import { logger } from './config/logger';

app.listen(config.port, () => {
  logger.info(`⚡ CyberShield OS Enterprise SOC Server running on port ${config.port}`);
});
