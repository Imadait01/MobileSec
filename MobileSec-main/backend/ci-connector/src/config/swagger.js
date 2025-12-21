/**
 * Swagger Configuration for CI-Connector
 */

const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'CI-Connector API',
            version: '2.0.0',
            description: `
API pour l'intégration CI/CD avec les scans de sécurité.

**Fonctionnalités:**
- Déclenche les scans APK depuis les pipelines CI/CD
- Crée des entrées de scan dans MongoDB
- Appelle APK-Scanner pour lancer l'analyse
- Suit le statut des scans

**Architecture:**
- Point d'entrée pour les scans (depuis GitHub Actions, GitLab CI, etc.)
- Écrit dans MongoDB (collection: scans)
- Appelle APK-Scanner pour démarrer l'analyse
            `,
            contact: {
                name: 'Security Platform Team'
            }
        },
        servers: [
            {
                url: 'http://localhost:3000',
                description: 'Serveur de développement'
            },
            {
                url: 'http://ci-connector:3000',
                description: 'Serveur Docker'
            }
        ],
        tags: [
            { name: 'Health', description: 'Endpoints de santé' },
            { name: 'Trigger', description: 'Déclenchement de scans' },
            { name: 'Scans', description: 'Gestion des scans' },
            { name: 'Statistics', description: 'Statistiques' }
        ]
    },
    apis: ['./src/routes/*.js', './src/app.js']
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = { swaggerSpec };
