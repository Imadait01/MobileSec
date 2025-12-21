/**
 * Swagger Configuration for ReportGen
 */

const swaggerSpec = {
    openapi: '3.0.0',
    info: {
        title: 'ReportGen API',
        version: '2.0.0',
        description: `
API pour la génération de rapports de sécurité consolidés.

**Fonctionnalités:**
- Consolide les résultats de tous les analyseurs (APK, Secrets, Crypto, Network)
- Génère des rapports PDF et HTML
- Stocke les rapports dans MongoDB

**Architecture:**
- Lit les données depuis MongoDB (collections: apk_results, secret_results, crypto_results, network_results)
- Écrit les rapports dans MongoDB (collection: reports)
        `,
        contact: {
            name: 'Security Platform Team'
        }
    },
    servers: [
        {
            url: 'http://localhost:3005',
            description: 'Serveur de développement'
        }
    ],
    tags: [
        { name: 'Health', description: 'Endpoints de santé' },
        { name: 'Reports', description: 'Génération et gestion des rapports' },
        { name: 'Statistics', description: 'Statistiques' }
    ],
    paths: {
        '/health': {
            get: {
                summary: 'Vérifier la santé du service',
                tags: ['Health'],
                responses: {
                    '200': {
                        description: 'Service en bonne santé',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        status: { type: 'string', example: 'healthy' },
                                        service: { type: 'string', example: 'ReportGen' },
                                        version: { type: 'string', example: '2.0.0' },
                                        mongodb: { type: 'boolean', example: true }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        '/api/reports/generate': {
            post: {
                summary: 'Génère un nouveau rapport de sécurité',
                tags: ['Reports'],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['projectName', 'scanResults'],
                                properties: {
                                    projectName: { type: 'string', example: 'MonApplication' },
                                    scanId: { type: 'string', example: '38d1e1e8-7fdc-408f-b8c8-08edf12f04ae' },
                                    format: { type: 'string', enum: ['pdf', 'json', 'sarif'], default: 'json' },
                                    scanResults: {
                                        type: 'object',
                                        properties: {
                                            sast: { type: 'array', items: { type: 'object' } },
                                            secrets: { type: 'array', items: { type: 'object' } },
                                            sca: { type: 'array', items: { type: 'object' } },
                                            dast: { type: 'array', items: { type: 'object' } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                responses: {
                    '200': { description: 'Rapport en cours de génération' },
                    '400': { description: 'Erreur de validation' }
                }
            }
        },
        '/api/reports/generate-from-scan': {
            post: {
                summary: 'Génère un rapport depuis MongoDB avec scan_id',
                description: 'Lit automatiquement les résultats de CryptoCheck, SecretHunter, NetworkInspector depuis MongoDB',
                tags: ['Reports'],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                required: ['scanId'],
                                properties: {
                                    scanId: { type: 'string', example: '38d1e1e8-7fdc-408f-b8c8-08edf12f04ae' },
                                    projectName: { type: 'string', example: 'MonApp' },
                                    format: { type: 'string', enum: ['pdf', 'json', 'sarif'], default: 'json' }
                                }
                            }
                        }
                    }
                },
                responses: {
                    '202': { description: 'Rapport en cours de génération' },
                    '404': { description: 'Scan non trouvé' }
                }
            }
        },
        '/api/reports': {
            get: {
                summary: 'Liste tous les rapports générés',
                tags: ['Reports'],
                parameters: [
                    { name: 'page', in: 'query', schema: { type: 'integer' } },
                    { name: 'limit', in: 'query', schema: { type: 'integer' } }
                ],
                responses: {
                    '200': {
                        description: 'Liste des rapports',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        total: { type: 'integer' },
                                        data: { type: 'array' }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        '/api/reports/{reportId}': {
            get: {
                summary: 'Récupère les informations d\'un rapport',
                tags: ['Reports'],
                parameters: [
                    { name: 'reportId', in: 'path', required: true, schema: { type: 'string' } }
                ],
                responses: {
                    '200': { description: 'Informations du rapport' },
                    '404': { description: 'Rapport non trouvé' }
                }
            },
            delete: {
                summary: 'Supprime un rapport',
                tags: ['Reports'],
                parameters: [
                    { name: 'reportId', in: 'path', required: true, schema: { type: 'string' } }
                ],
                responses: {
                    '200': { description: 'Rapport supprimé' },
                    '404': { description: 'Rapport non trouvé' }
                }
            }
        },
        '/api/reports/{reportId}/download': {
            get: {
                summary: 'Télécharge le fichier du rapport',
                tags: ['Reports'],
                parameters: [
                    { name: 'reportId', in: 'path', required: true, schema: { type: 'string' } }
                ],
                responses: {
                    '200': { description: 'Fichier du rapport' },
                    '404': { description: 'Rapport non trouvé' }
                }
            }
        },
        '/api/reports/{reportId}/vulnerabilities': {
            get: {
                summary: 'Récupère les vulnérabilités d\'un rapport',
                tags: ['Reports'],
                parameters: [
                    { name: 'reportId', in: 'path', required: true, schema: { type: 'string' } },
                    { name: 'page', in: 'query', schema: { type: 'integer' } },
                    { name: 'limit', in: 'query', schema: { type: 'integer' } },
                    { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] } }
                ],
                responses: {
                    '200': { description: 'Liste des vulnérabilités' },
                    '404': { description: 'Rapport non trouvé' }
                }
            }
        },
        '/api/reports/upload': {
            post: {
                summary: 'Génère un rapport à partir d\'un fichier JSON uploadé',
                tags: ['Reports'],
                requestBody: {
                    required: true,
                    content: {
                        'multipart/form-data': {
                            schema: {
                                type: 'object',
                                properties: {
                                    file: { type: 'string', format: 'binary' }
                                }
                            }
                        }
                    }
                },
                responses: {
                    '200': { description: 'Rapport généré' }
                }
            }
        },
        '/api/reports/input-files': {
            get: {
                summary: 'Liste les fichiers dans le dossier input',
                tags: ['Reports'],
                responses: {
                    '200': { description: 'Liste des fichiers' }
                }
            },
            delete: {
                summary: 'Vide le dossier input',
                tags: ['Reports'],
                responses: {
                    '200': { description: 'Dossier vidé' }
                }
            }
        }
    }
};

export { swaggerSpec };
