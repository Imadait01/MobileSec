const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');


const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Gateway',
      version: '1.0.0',
      description: 'API Gateway for microservices with Kafka and MongoDB',
    },
    servers: [
      { url: 'http://localhost:8082', description: 'Local server' }
    ],
  },
  apis: ['./index.js'], // index.js contient la doc de l'upload APK
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = { swaggerSpec, swaggerUi };
