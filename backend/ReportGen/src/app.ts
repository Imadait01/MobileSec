import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import logger from './utils/logger';
import reportRoutes from './routes/report.routes';
import { kafkaService } from './services/kafkaService';
import { mongoClient } from './database/mongodb';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/api/reports', reportRoutes);

app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'reportgen' }));
app.get('/health', (_req, res) => res.json({ ok: true, service: 'reportgen' }));

const port = Number(process.env.PORT || 3006);

async function start() {
  try {
    await mongoClient.connect();
    await kafkaService.connect();
    app.listen(port, () => logger.info(`ReportGen listening on port ${port}`));
  } catch (e) {
    logger.error('Failed to start ReportGen', { error: e });
    process.exit(1);
  }
}

start();

export default app;
