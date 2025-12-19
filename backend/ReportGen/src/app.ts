import dotenv from 'dotenv';
import express, { Express } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cron from 'node-cron';
import fs from 'fs/promises';
import swaggerUi from 'swagger-ui-express';

// Charger les variables d'environnement
dotenv.config();

import logger from './utils/logger';
import reportRoutes from './routes/report.routes';
import {
  errorHandler,
  notFoundHandler,
  requestLogger,
  errorLogger
} from './middlewares';
import { reportController } from './controllers/report.controller';
import { mongoClient } from './database/mongodb';
import { swaggerSpec } from './config/swagger';

// Créer l'application Express
const app: Express = express();

// Configuration
const PORT = parseInt(process.env.PORT || '3005', 10);
const MAX_PAYLOAD_SIZE = process.env.MAX_PAYLOAD_SIZE || '50mb';
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '10', 10);
const RATE_LIMIT_WINDOW = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const TEMP_DIR = process.env.TEMP_DIR || './tmp';

// Créer le dossier temporaire au démarrage
async function ensureTempDir(): Promise<void> {
  try {
    await fs.mkdir(TEMP_DIR, { recursive: true });
    logger.info(`Temp directory ensured: ${TEMP_DIR}`);
  } catch (error) {
    logger.error('Failed to create temp directory', { error });
  }
}

// Middlewares globaux
app.use(cors());
app.use(express.json({ limit: MAX_PAYLOAD_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_PAYLOAD_SIZE }));

// Logging des requêtes
app.use(requestLogger);

// Swagger UI
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Rate limiting
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: {
    error: 'Too many requests',
    message: `Maximum ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW / 1000} seconds`,
    retryAfter: RATE_LIMIT_WINDOW / 1000
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' // Ne pas limiter le health check
});

app.use('/api', limiter);

/**
 * @swagger
 * /health:
 *   get:
 *     tags: [Health]
 *     summary: Vérification de santé du service
 *     responses:
 *       200:
 *         description: Statut de santé
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'ReportGen',
    version: '2.0.0',
    mongodb: mongoClient.isConnected(),
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * Alias de santé pour API Gateway
 */
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'ReportGen',
    version: '2.0.0',
    mongodb: mongoClient.isConnected(),
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Routes API
app.use('/api/reports', reportRoutes);

// Route racine
app.get('/', (_req, res) => {
  res.json({
    service: 'ReportGen',
    description: 'Security Report Generation Microservice',
    version: '2.0.0',
    swagger: '/swagger',
    mongodb_connected: mongoClient.isConnected(),
    endpoints: {
      health: 'GET /health',
      swagger: 'GET /swagger',
      generateFromMongo: 'POST /api/reports/generate-from-scan',
      generateReport: 'POST /api/reports/generate',
      listReports: 'GET /api/reports',
      getReport: 'GET /api/reports/:reportId',
      downloadReport: 'GET /api/reports/:reportId/download',
      getVulnerabilities: 'GET /api/reports/:reportId/vulnerabilities',
      deleteReport: 'DELETE /api/reports/:reportId',
      stats: 'GET /api/reports/stats'
    }
  });
});

// Logging des erreurs
app.use(errorLogger);

// Gestion des routes non trouvées
app.use(notFoundHandler);

// Gestion globale des erreurs
app.use(errorHandler);

// Tâche CRON pour nettoyer les rapports expirés (toutes les heures)
cron.schedule('0 * * * *', async () => {
  logger.info('Running scheduled cleanup of expired reports');
  try {
    const deletedCount = await reportController.cleanupExpiredReports();
    logger.info(`Cleanup completed: ${deletedCount} reports deleted`);
  } catch (error) {
    logger.error('Failed to cleanup expired reports', { error });
  }
});

// Gestion des signaux de terminaison
const gracefulShutdown = (signal: string) => {
  logger.info(`Received ${signal}. Shutting down gracefully...`);

  // Donner un peu de temps pour terminer les requêtes en cours
  setTimeout(() => {
    logger.info('Shutting down...');
    process.exit(0);
  }, 5000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Gestion des erreurs non capturées
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', { reason, promise });
});

// Démarrer le serveur
async function startServer(): Promise<void> {
  await ensureTempDir();

  // Connect to MongoDB
  const mongoConnected = await mongoClient.connect();
  if (!mongoConnected) {
    logger.warn('MongoDB connection failed, will retry on first request');
  }

  // Start Kafka Consumer
  try {
    const { kafkaService } = await import('./services/kafkaService');
    await kafkaService.connect();
  } catch (error) {
    logger.error('Failed to start Kafka consumer', { error });
  }
  if (!mongoConnected) {
    logger.warn('MongoDB connection failed, will retry on first request');
  }

  app.listen(PORT, () => {
    logger.info(`🚀 ReportGen service started`, {
      port: PORT,
      environment: process.env.NODE_ENV || 'development',
      tempDir: TEMP_DIR,
      rateLimitMax: RATE_LIMIT_MAX,
      rateLimitWindow: `${RATE_LIMIT_WINDOW / 1000}s`,
      mongodb: mongoConnected
    });

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔒 ReportGen Security Report Generator v2.0                ║
║                                                              ║
║   Server running on http://localhost:${PORT}                    ║
║   Swagger UI: http://localhost:${PORT}/swagger                  ║
║   MongoDB: ${mongoConnected ? 'Connected ✅' : 'Disconnected ❌'}                               ║
║                                                              ║
║   Endpoints:                                                 ║
║   • Health:     GET  /health                                 ║
║   • Swagger:    GET  /swagger                                ║
║   • Generate:   POST /api/reports/generate-from-scan         ║
║   • List:       GET  /api/reports                            ║
║   • Stats:      GET  /api/reports/stats                      ║
║   • Info:       GET  /api/reports/:id                        ║
║   • Download:   GET  /api/reports/:id/download               ║
║   • Delete:     DELETE /api/reports/:id                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `);
  });
}

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

export default app;
