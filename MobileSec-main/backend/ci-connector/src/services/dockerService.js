const { exec } = require('child_process');
const { promisify } = require('util');
const winston = require('winston');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

const execAsync = promisify(exec);

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
 * Service pour gérer les interactions avec Docker
 */
class DockerService {
  /**
   * Vérifie si Docker est disponible
   */
  async checkDockerStatus() {
    try {
      const { stdout } = await execAsync('docker --version');
      logger.info('Docker is available');
      return {
        available: true,
        version: stdout.trim()
      };
    } catch (error) {
      logger.error('Docker is not available');
      return {
        available: false,
        error: error.message
      };
    }
  }

  /**
   * Lance le scanner APKScanner via API HTTP
   * @param {string} apkPath - Chemin vers le fichier APK/AAB
   * @returns {Promise<Object>} - Résultat du scan
   */
  async runAPKScanner(apkPath) {
    try {
      const fileName = path.basename(apkPath);
      const APK_SCANNER_URL = process.env.APK_SCANNER_URL || 'http://apk-scanner:5000';

      logger.info(`Calling APKScanner API for: ${fileName}`);
      logger.info(`APK file path: ${apkPath}`);

      // Vérifier que le fichier existe
      if (!fs.existsSync(apkPath)) {
        throw new Error(`APK file not found: ${apkPath}`);
      }

      // Créer FormData pour l'upload
      const formData = new FormData();
      formData.append('file', fs.createReadStream(apkPath), {
        filename: fileName,
        contentType: 'application/vnd.android.package-archive'
      });

      // Appeler l'API APKScanner
      const response = await axios.post(`${APK_SCANNER_URL}/scan-apk`, formData, {
        headers: formData.getHeaders(),
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        timeout: 300000 // 5 minutes timeout
      });

      logger.info('APKScanner API call completed successfully');
      logger.info(`Scan result - Package: ${response.data.package_name}, Score: ${response.data.security_score?.score}`);

      return {
        scanner: 'apk-scanner',
        status: 'completed',
        result: response.data
      };
    } catch (error) {
      logger.error(`APKScanner API error: ${error.message}`);
      if (error.response) {
        logger.error(`Response status: ${error.response.status}`);
        logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
      }
      throw new Error(`APKScanner failed: ${error.message}`);
    }
  }

  /**
   * Lance le scanner NetworkInspector via Docker (DEPRECATED)
   * NetworkInspector est maintenant appelé par APKScanner
   * @deprecated Cette méthode n'est plus utilisée dans l'architecture actuelle
   * @param {string} apkPath - Chemin vers le fichier APK/AAB
   * @returns {Promise<Object>} - Résultat du scan
   */
  async runNetworkInspector(apkPath) {
    logger.warn('runNetworkInspector is deprecated. NetworkInspector should be called by APKScanner.');
    throw new Error('NetworkInspector should be called by APKScanner, not directly by CIConnector');
  }

  /**
   * Lance un container Docker personnalisé
   * @param {string} imageName - Nom de l'image Docker
   * @param {string} apkPath - Chemin vers le fichier APK/AAB
   * @param {Object} options - Options supplémentaires
   * @returns {Promise<Object>} - Résultat de l'exécution
   */
  async runCustomScanner(imageName, apkPath, options = {}) {
    try {
      const absolutePath = path.resolve(apkPath);
      const fileName = path.basename(apkPath);
      const dirName = path.dirname(absolutePath);

      logger.info(`Running custom scanner: ${imageName}`);

      // Construire la commande Docker
      let command = `docker run --rm`;

      // Ajouter les volumes
      command += ` -v "${dirName}:/app/input"`;
      
      if (options.outputVolume) {
        command += ` -v "${options.outputVolume}:/app/output"`;
      }

      // Ajouter les variables d'environnement
      if (options.env) {
        Object.keys(options.env).forEach(key => {
          command += ` -e ${key}="${options.env[key]}"`;
        });
      }

      // Ajouter l'image et la commande
      command += ` ${imageName}`;
      
      if (options.command) {
        command += ` ${options.command}`;
      } else {
        command += ` /app/input/${fileName}`;
      }

      const { stdout, stderr } = await execAsync(command, {
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });

      logger.info(`Custom scanner ${imageName} completed`);

      return {
        scanner: imageName,
        containerId: 'completed',
        logs: stdout || stderr,
        status: 'success'
      };
    } catch (error) {
      logger.error(`Custom scanner ${imageName} error: ${error.message}`);
      throw new Error(`Custom scanner failed: ${error.message}`);
    }
  }

  /**
   * Liste les containers Docker en cours d'exécution
   * @returns {Promise<Array>} - Liste des containers
   */
  async listRunningContainers() {
    try {
      const { stdout } = await execAsync('docker ps --format "{{.ID}}|{{.Image}}|{{.Status}}"');
      
      const containers = stdout.trim().split('\n')
        .filter(line => line.length > 0)
        .map(line => {
          const [id, image, status] = line.split('|');
          return { id, image, status };
        });

      return containers;
    } catch (error) {
      logger.error(`Failed to list containers: ${error.message}`);
      return [];
    }
  }

  /**
   * Arrête un container Docker
   * @param {string} containerId - ID du container
   * @returns {Promise<boolean>} - Succès ou échec
   */
  async stopContainer(containerId) {
    try {
      await execAsync(`docker stop ${containerId}`);
      logger.info(`Container ${containerId} stopped`);
      return true;
    } catch (error) {
      logger.error(`Failed to stop container ${containerId}: ${error.message}`);
      return false;
    }
  }

  /**
   * Nettoie les volumes Docker inutilisés
   * @returns {Promise<Object>} - Résultat du nettoyage
   */
  async cleanupVolumes() {
    try {
      const { stdout } = await execAsync('docker volume prune -f');
      logger.info('Docker volumes cleaned up');
      return {
        success: true,
        output: stdout
      };
    } catch (error) {
      logger.error(`Failed to cleanup volumes: ${error.message}`);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new DockerService();
