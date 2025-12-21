const express = require('express');
const router = express.Router();
const winston = require('winston');
const dockerService = require('../services/dockerService');
const yamlGenerator = require('../services/yamlGenerator');
const fs = require('fs');
const path = require('path');

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
    })
  ]
});

/**
 * POST /api/trigger
 * Déclenche les scans de sécurité pour un APK ou AAB
 */
router.post('/trigger', async (req, res) => {
  try {
    const { apkPath, scanners } = req.body;

    // Validation des entrées
    if (!apkPath) {
      return res.status(400).json({
        error: 'Missing required parameter: apkPath'
      });
    }

    // Vérifier que le fichier existe
    if (!fs.existsSync(apkPath)) {
      return res.status(404).json({
        error: 'File not found',
        path: apkPath
      });
    }

    logger.info(`Triggering security scans for: ${apkPath}`);

    // CIConnector appelle uniquement APKScanner
    // APKScanner se chargera ensuite d'appeler NetworkInspector
    const results = {
      status: 'success',
      apkPath,
      timestamp: new Date().toISOString(),
      scans: []
    };

    // Lancer APKScanner (qui appellera NetworkInspector automatiquement)
    logger.info('Launching APKScanner...');
    try {
      const apkScanResult = await dockerService.runAPKScanner(apkPath);
      results.scans.push({
        scanner: 'apk-scanner',
        status: apkScanResult.status,
        result: apkScanResult.result
      });
      logger.info('APKScanner completed successfully (including NetworkInspector)');
      
      // Afficher le score de sécurité
      if (apkScanResult.result?.security_score) {
        logger.info(`Security Score: ${apkScanResult.result.security_score.score}/100 (Grade ${apkScanResult.result.security_score.grade})`);
      }
    } catch (error) {
      logger.error(`APKScanner failed: ${error.message}`);
      results.scans.push({
        scanner: 'apk-scanner',
        status: 'failed',
        error: error.message
      });
      results.status = 'failed';
      return res.status(500).json(results);
    }

    res.json(results);

  } catch (error) {
    logger.error(`Trigger endpoint error: ${error.message}`);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @swagger
 * /api/generate-ci:
 *   post:
 *     tags: [Trigger]
 *     summary: Génère les fichiers de configuration CI/CD (GitHub Actions/GitLab CI)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               platform:
 *                 type: string
 *                 description: Plateforme cible (github, gitlab, both)
 *                 example: github
 *               outputPath:
 *                 type: string
 *                 description: Chemin de sortie pour les fichiers générés (optionnel)
 *                 example: /app
 *     responses:
 *       200:
 *         description: Fichiers CI/CD générés avec succès
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 message:
 *                   type: string
 *                 files:
 *                   type: array
 *                   items:
 *                     type: string
 *       400:
 *         description: Paramètre manquant ou invalide
 *       500:
 *         description: Erreur interne lors de la génération
 */
router.post('/generate-ci', async (req, res) => {
  try {

    const { platform, outputPath } = req.body;

    // Validation
    if (!platform) {
      return res.status(400).json({
        error: 'Missing required parameter: platform',
        validPlatforms: ['github', 'gitlab', 'both']
      });
    }

    // Correction : si outputPath est vide, null ou non défini, utiliser /tmp (toujours accessible en écriture)
    let basePath = '/tmp';
    if (outputPath && typeof outputPath === 'string' && outputPath.trim() !== '') {
      basePath = outputPath;
    }
    const generatedFiles = [];

    logger.info(`Generating CI configuration for platform: ${platform}`);

    // Générer pour GitHub Actions
    if (platform === 'github' || platform === 'both') {
      const githubYaml = yamlGenerator.generateGitHubActions();
      const githubPath = path.join(basePath, '.github', 'workflows', 'security_scan.yml');
      
      // Créer le répertoire si nécessaire
      const dir = path.dirname(githubPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(githubPath, githubYaml);
      generatedFiles.push(githubPath);
      logger.info(`GitHub Actions workflow created: ${githubPath}`);
    }

    // Générer pour GitLab CI
    if (platform === 'gitlab' || platform === 'both') {
      const gitlabYaml = yamlGenerator.generateGitLabCI();
      const gitlabPath = path.join(basePath, '.gitlab-ci.yml');
      
      fs.writeFileSync(gitlabPath, gitlabYaml);
      generatedFiles.push(gitlabPath);
      logger.info(`GitLab CI configuration created: ${gitlabPath}`);
    }

    res.json({
      status: 'success',
      message: 'CI configuration files generated successfully',
      files: generatedFiles
    });

  } catch (error) {
    logger.error(`Generate CI endpoint error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to generate CI configuration',
      message: error.message
    });
  }
});

/**
 * GET /api/status
 * Vérifie le statut du service et la disponibilité de Docker
 */
router.get('/status', async (req, res) => {
  try {
    const dockerStatus = await dockerService.checkDockerStatus();
    
    res.json({
      service: 'CIConnector',
      status: 'running',
      docker: dockerStatus,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      service: 'CIConnector',
      status: 'running',
      docker: {
        available: false,
        error: error.message
      },
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;
