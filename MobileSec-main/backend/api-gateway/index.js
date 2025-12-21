
const express = require('express');
const app = express();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Swagger setup
const { Kafka } = require('kafkajs');
const kafka = new Kafka({
  clientId: 'api-gateway',
  brokers: [process.env.KAFKA_BROKER || 'kafka:9092']
});
const consumer = kafka.consumer({ groupId: 'api-gateway-group' });

const mongoose = require('mongoose');
const { swaggerSpec, swaggerUi } = require('./swagger');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

app.use(cors({
  origin: '*', // Allow all origins for dev simplicity, or specify 'http://localhost:3006'
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Proxy configuration
const proxyOptions = {
  changeOrigin: true,
  pathRewrite: {
    '^/api/apk': '/api',
    '^/api/secrets': '/api',
    '^/api/network': '/api',
    '^/api/crypto': '/api',
    '^/api/fix': '/api',
    '^/api/ci': '',
    '^/api/report': '',
  },
  onProxyReq: (proxyReq, req, res) => {
    // Optional: Log proxy requests
    // console.log(`[Proxy] ${req.method} ${req.path} -> ${proxyReq.host}`);
  }
};

app.use('/api/apk', createProxyMiddleware({ ...proxyOptions, target: process.env.APK_SCANNER_URL || 'http://apk-scanner:5000' }));
app.use('/api/scan', createProxyMiddleware({ ...proxyOptions, target: process.env.APK_SCANNER_URL || 'http://apk-scanner:5000' }));
app.use('/api/secrets', createProxyMiddleware({ ...proxyOptions, target: process.env.SECRET_HUNTER_URL || 'http://secret-hunter:5002' }));
app.use('/api/network', createProxyMiddleware({ ...proxyOptions, target: process.env.NETWORK_INSPECTOR_URL || 'http://network-inspector:5001' }));
app.use('/api/crypto', createProxyMiddleware({ ...proxyOptions, target: process.env.CRYPTO_CHECK_URL || 'http://crypto-check:8080' }));
app.use('/api/fix', createProxyMiddleware({ ...proxyOptions, target: process.env.FIX_SUGGEST_URL || 'http://fixsuggest:8000' }));
app.use('/api/ci', createProxyMiddleware({ ...proxyOptions, target: process.env.CI_CONNECTOR_URL || 'http://ci-connector:3000' }));
app.use('/api/report', createProxyMiddleware({ ...proxyOptions, target: process.env.REPORT_GEN_URL || 'http://reportgen:3005' }));


// Multer setup - MEMORY STORAGE to avoid disk WRITE errors
const upload = multer({ storage: multer.memoryStorage() });

// MongoDB setup
mongoose.connect(process.env.MONGODB_URI || 'mongodb://mongodb:27017/microservices');
const Payload = mongoose.model('Payload', new mongoose.Schema({ data: Object, scanResult: Object }));

/**
 * @swagger
 * /api/ingest:
 *   post:
 *     summary: Ingest a large JSON payload or upload an APK file
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               description:
 *                 type: string
 *               apkName:
 *                 type: string
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Payload ingested and queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 id:
 *                   type: string
 */
app.post('/api/ingest', upload.single('file'), async (req, res) => {
  console.log('[API-GATEWAY] /api/ingest called');
  if (!req.file) {
    console.log('[API-GATEWAY] No file uploaded');
    return res.status(400).json({ status: 'error', message: 'No file uploaded' });
  }

  console.log('[API-GATEWAY] File received in memory. Size:', req.file.size);

  // Transmettre le fichier à apk-scanner via un POST multipart
  const axios = require('axios');
  const FormData = require('form-data');

  try {
    const form = new FormData();
    // Use buffer directly from memory
    form.append('file', req.file.buffer, req.file.originalname);

    if (req.body.description) form.append('description', req.body.description);
    if (req.body.apkName) form.append('apkName', req.body.apkName);

    console.log('[API-GATEWAY] Forwarding file buffer to apk-scanner...');
    const response = await axios.post(
      process.env.APK_SCANNER_URL || 'http://apk-scanner:5000/api/scan',
      form,
      {
        headers: {
          ...form.getHeaders(),
          'Content-Length': form.getLengthSync()
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        timeout: 60000
      }
    );
    console.log('[API-GATEWAY] apk-scanner response:', response.status, response.data);
    res.status(response.status).json(response.data);
  } catch (err) {
    console.error('[API-GATEWAY] Error forwarding to apk-scanner:', err.message);
    if (err.response) {
      console.error('[API-GATEWAY] Target response:', err.response.data);
    }
    res.status(500).json({ status: 'error', message: err.message });
  }
});


// Kafka consumer logic 
async function startConsumer() {
  try {
    await consumer.connect();
    await consumer.subscribe({ topic: 'scan-results', fromBeginning: true });
    consumer.run({
      eachMessage: async ({ message }) => {
        const { id, scanResult } = JSON.parse(message.value.toString());
        await Payload.findByIdAndUpdate(id, { $set: { scanResult } });
      }
    });
  } catch (e) {
    console.error('Kafka consumer error:', e);
  }
}
startConsumer();

// Swagger UI for API Gateway itself
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Minimal implementation for /api/result/:id 
app.get('/api/result/:id', async (req, res) => {
  res.json({ status: 'ok', id: req.params.id, result: null });
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`API Gateway running on port ${PORT}`));
