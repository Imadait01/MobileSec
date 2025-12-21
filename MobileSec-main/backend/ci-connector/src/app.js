const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const winston = require('winston');
const swaggerUi = require('swagger-ui-express');
const triggerRoutes = require('./routes/trigger');
const { mongoClient } = require('./database/mongodb');
const { swaggerSpec } = require('./config/swagger');

// Configuration du logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Logger middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`);
  next();
});

// Swagger UI
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /:
 *   get:
 *     tags: [Health]
 *     summary: Page d'accueil de l'API
 *     responses:
 *       200:
 *         description: Informations sur le service
 */
app.get('/', (req, res) => {
  res.json({
    service: 'CIConnector',
    version: '2.0.0',
    status: 'running',
    swagger: '/swagger',
    mongodb_connected: mongoClient.isConnected(),
    description: 'Microservice pour l\'intégration CI/CD avec scans de sécurité automatiques',
    endpoints: {
      health: 'GET /health',
      swagger: 'GET /swagger',
      trigger: 'POST /api/trigger',
      scans: 'GET /api/scans',
      scan: 'GET /api/scans/:scanId',
      stats: 'GET /api/stats'
    }
  });
});

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
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'CIConnector',
    mongodb: mongoClient.isConnected(),
    timestamp: new Date().toISOString()
  });
});

/**
 * Alias de santé pour API Gateway
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'CIConnector',
    mongodb: mongoClient.isConnected(),
    timestamp: new Date().toISOString()
  });
});

app.use('/api', triggerRoutes);

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Gestion des erreurs globales
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Démarrage du serveur
async function startServer() {
  // Connect to MongoDB
  const mongoConnected = await mongoClient.connect();
  if (!mongoConnected) {
    logger.warn('MongoDB connection failed, will retry on first request');
  }

  app.listen(PORT, () => {
    logger.info(`CIConnector service started on port ${PORT}`);
    logger.info(`MongoDB: ${mongoConnected ? 'Connected' : 'Disconnected'}`);
    logger.info(`Swagger UI: http://localhost:${PORT}/swagger`);
    logger.info('Ready to process security scans');
  });
}

startServer();

// Export pour les tests
module.exports = app;
