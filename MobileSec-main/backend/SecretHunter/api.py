"""
SecretHunter API Server
Flask API for detecting secrets in decompiled APK code.
Reads input from MongoDB (apk_results), writes output to MongoDB (secret_results).

API Documentation: /swagger/
"""



import os
import sys
import threading
import json
import logging
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from flasgger import Swagger
from datetime import datetime
try:
    from confluent_kafka import Consumer
except ImportError:
    Consumer = None
    print("!!! confluent_kafka import failed !!!", flush=True)

print(f"!!! Consumer available: {Consumer is not None} !!!", flush=True)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Kafka Consumer moved to end of file to ensure all dependencies are loaded

from database.mongodb_client import mongodb_client
from core.file_scanner import FileScanner
from core.yara_scanner import YaraScanner
from core.aggregator import ResultAggregator

# Configuration
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/app/uploads')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER', '/app/output')
RULES_PATH = os.getenv('RULES_PATH', 'rules/regex_patterns.json')
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', 'rules/secrets.yar')
# Path remapping: APK-Scanner writes to /app/decompiled, we read from /app/apk-input
APK_INPUT_PATH = os.getenv('APK_INPUT_PATH', '/app/apk-input')
APK_SCANNER_PATH = '/app/decompiled'  # Path as stored by APK-Scanner

# Create directories
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(OUTPUT_FOLDER).mkdir(exist_ok=True)
Path('logs').mkdir(exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/secret_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
CORS(app)

# Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger/"
}

swagger_template = {
    "info": {
        "title": "SecretHunter API",
        "description": "API pour la détection de secrets dans le code décompilé. Lit depuis MongoDB (apk_results), écrit dans MongoDB (secret_results).",
        "version": "2.0.0",
        "contact": {"name": "Security Platform Team"}
    },
    "basePath": "/",
    "schemes": ["http", "https"],
    "tags": [
        {"name": "Health", "description": "Endpoints de santé"},
        {"name": "Analyze", "description": "Endpoints d'analyse"},
        {"name": "Results", "description": "Endpoints de résultats"},
        {"name": "Statistics", "description": "Endpoints de statistiques"}
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)


def perform_secret_scan(scan_id: str, decompiled_path: str) -> dict:
    """
    Perform secret scanning on decompiled code.
    
    Args:
        scan_id: Unique scan identifier
        decompiled_path: Path to decompiled APK code
        
    Returns:
        dict: Scan results with secrets found
    """
    logger.info(f"Starting secret scan for scan_id: {scan_id}")
    
    aggregator = ResultAggregator()
    
    try:
        # 1. Regex-based file scanning
        logger.info("Running regex-based file scanner...")
        file_scanner = FileScanner(rules_path=RULES_PATH)
        file_findings = file_scanner.scan_directory(decompiled_path)
        aggregator.add_findings(file_findings, 'file_scanner')
        logger.info(f"File scanner found {len(file_findings)} potential secrets")
        
        # 2. YARA rules scanning
        if os.path.exists(YARA_RULES_PATH):
            logger.info("Running YARA scanner...")
            yara_scanner = YaraScanner(rules_path=YARA_RULES_PATH)
            yara_findings = yara_scanner.scan_directory(decompiled_path)
            aggregator.add_findings(yara_findings, 'yara_scanner')
            logger.info(f"YARA scanner found {len(yara_findings)} potential secrets")
        else:
            logger.warning(f"YARA rules not found at {YARA_RULES_PATH}")
        
        # Generate report
        report = aggregator.generate_report()
        
        return report
        
    except Exception as e:
        logger.error(f"Secret scan failed: {e}", exc_info=True)
        raise


def calculate_severity_summary(secrets: list) -> dict:
    """Calculate severity distribution of found secrets"""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for secret in secrets:
        severity = secret.get("severity", "low").lower()
        if severity in summary:
            summary[severity] += 1
        else:
            summary["info"] += 1
    
    return summary


# ============= API ROUTES =============

@app.route('/', methods=['GET'])
def index():
    """
    Page d'accueil de l'API
    ---
    tags:
      - Health
    responses:
      200:
        description: Informations sur le service
    """
    return jsonify({
        'service': 'SecretHunter',
        'version': '2.0.0',
        'description': 'Secret detection in decompiled APK code',
        'swagger': '/swagger/',
        'mongodb_connected': mongodb_client.is_connected()
    })


@app.route('/health', methods=['GET'])
def health_check():
    """
    Vérification de santé du service
    ---
    tags:
      - Health
    responses:
      200:
        description: Statut de santé
    """
    return jsonify({
        'status': 'healthy',
        'mongodb': mongodb_client.is_connected(),
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'SecretHunter'
    })


@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Alias for health check compatible with Gateway"""
    return health_check()


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyser les secrets dans le code décompilé (appelé par APK-Scanner)
    ---
    tags:
      - Analyze
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - scan_id
          properties:
            scan_id:
              type: string
              description: ID du scan (résultats APK dans MongoDB)
    responses:
      200:
        description: Analyse terminée
      400:
        description: Paramètres manquants
      404:
        description: Résultats APK non trouvés
      500:
        description: Erreur serveur
    """
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        
        if not scan_id:
            return jsonify({'error': 'scan_id is required'}), 400
        
        # Update status
        mongodb_client.update_scan_stage(scan_id, 'in_progress')
        
        # Get APK results from MongoDB
        apk_results = mongodb_client.get_apk_results(scan_id)
        if not apk_results:
            mongodb_client.update_scan_stage(scan_id, 'failed')
            return jsonify({'error': 'APK results not found in MongoDB'}), 404
        
        # Get decompiled path and remap it
        results_data = apk_results.get('results', apk_results)
        decompiled_path = results_data.get('decompiled_path')
        
        # Remap path: APK-Scanner stores /app/decompiled/xxx, we have it mounted at /app/apk-input
        if decompiled_path and decompiled_path.startswith(APK_SCANNER_PATH):
            decompiled_path = decompiled_path.replace(APK_SCANNER_PATH, APK_INPUT_PATH)
            logger.info(f"Remapped path to: {decompiled_path}")
        
        if not decompiled_path or not os.path.exists(decompiled_path):
            mongodb_client.update_scan_stage(scan_id, 'failed')
            return jsonify({'error': f'Decompiled path not found: {decompiled_path}'}), 404
        
        # Perform secret scan
        report = perform_secret_scan(scan_id, decompiled_path)
        
        # Extract findings
        secrets = report.get('findings', [])
        summary = report.get('summary', {})
        
        # Save to MongoDB
        mongodb_client.save_secret_results(scan_id, secrets, summary)
        mongodb_client.update_scan_stage(scan_id, 'completed')
        
        logger.info(f"✅ Secret scan completed for {scan_id}: {len(secrets)} secrets found")
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'secrets_found': len(secrets),
            'summary': summary
        })
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {e}", exc_info=True)
        if scan_id:
            mongodb_client.update_scan_stage(scan_id, 'failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan', methods=['POST'])
def scan_directory():
    """
    Scanner un répertoire directement pour les secrets
    ---
    tags:
      - Analyze
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - scan_id
            - path
          properties:
            scan_id:
              type: string
              description: ID du scan
            path:
              type: string
              description: Chemin du répertoire à scanner
    responses:
      200:
        description: Scan terminé
      400:
        description: Paramètres manquants
      404:
        description: Répertoire non trouvé
      500:
        description: Erreur serveur
    """
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        path = data.get('path')
        if not scan_id or not path:
            return jsonify({'error': 'scan_id and path are required'}), 400
        # Remap path: APK-Scanner stores /app/decompiled/xxx, we have it mounted at /app/apk-input
        if path.startswith(APK_SCANNER_PATH):
            path = path.replace(APK_SCANNER_PATH, APK_INPUT_PATH)
            logger.info(f"Remapped path to: {path}")
        if not os.path.exists(path):
            return jsonify({'error': f'Path not found: {path}'}), 404
        # Perform scan
        report = perform_secret_scan(scan_id, path)
        secrets = report.get('findings', [])
        summary = report.get('summary', {})
        # Save to MongoDB
        mongodb_client.save_secret_results(scan_id, secrets, summary)
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'secrets_found': len(secrets),
            'secrets': secrets,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
        
        if not os.path.exists(path):
            return jsonify({'error': f'Path not found: {path}'}), 404
        
        # Perform scan
        report = perform_secret_scan(scan_id, path)
        secrets = report.get('findings', [])
        summary = report.get('summary', {})
        
        # Save to MongoDB
        mongodb_client.save_secret_results(scan_id, secrets, summary)
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'secrets_found': len(secrets),
            'secrets': secrets,
            'summary': summary
        })
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    """
    Récupérer les résultats de détection de secrets par ID
    ---
    tags:
      - Results
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
        description: ID du scan
    responses:
      200:
        description: Résultats des secrets
      404:
        description: Résultats non trouvés
    """
    try:
        results = mongodb_client.get_secret_results(scan_id)
        
        if not results:
            return jsonify({'error': 'Results not found'}), 404
        
        results['_id'] = str(results.get('_id', ''))
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/results', methods=['GET'])
def list_results():
    """
    Lister tous les résultats de détection de secrets
    ---
    tags:
      - Results
    parameters:
      - name: limit
        in: query
        type: integer
        required: false
        default: 100
    responses:
      200:
        description: Liste des résultats
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        results = mongodb_client.get_all_secret_results(limit)
        
        for r in results:
            r['_id'] = str(r.get('_id', ''))
        
        return jsonify({'count': len(results), 'results': results})
        
    except Exception as e:
        logger.error(f"Error listing results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/results/<scan_id>', methods=['DELETE'])
def delete_results(scan_id):
    """
    Supprimer les résultats de secrets
    ---
    tags:
      - Results
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Résultats supprimés
      404:
        description: Résultats non trouvés
    """
    try:
        deleted = mongodb_client.delete_secret_results(scan_id)
        
        if deleted:
            return jsonify({'message': 'Results deleted', 'scan_id': scan_id})
        else:
            return jsonify({'error': 'Results not found'}), 404
            
    except Exception as e:
        logger.error(f"Error deleting results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Récupérer les statistiques
    ---
    tags:
      - Statistics
    responses:
      200:
        description: Statistiques
    """
    try:
        stats = mongodb_client.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ============= KAFKA CONSUMER =============

def kafka_consumer_thread():
    if Consumer is None:
        logger.warning("confluent_kafka module not found. Kafka consumer disabled.")
        return

    conf = {
        'bootstrap.servers': os.getenv('KAFKA_BROKERS', 'kafka:9092'),
        'group.id': 'secrethunter-group',
        'auto.offset.reset': 'earliest'
    }

    try:
        print("Creating Consumer...", flush=True)
        consumer = Consumer(conf)
        print("Consumer created. Subscribing...", flush=True)
        consumer.subscribe(['scan-requests'])
        print("Subscribed. Starting poll loop...", flush=True)
        logger.info("Kafka consumer started manually: Listening to scan-requests")

        while True:
            # print("Polling...", flush=True) # Too noisy
            msg = consumer.poll(1.0)
            if msg is None: continue
            if msg.error():
                print(f"Kafka error: {msg.error()}", flush=True)
                logger.error(f"Kafka error: {msg.error()}")
                continue
            
            try:
                print(f"Message received: {msg.value()}", flush=True)
                data = json.loads(msg.value().decode('utf-8'))
                scan_id = data.get('id')
                if scan_id:
                    logger.info(f"[Kafka] Received scan request for {scan_id}")
                    # Reuse analysis logic safely
                    mongodb_client.update_scan_stage(scan_id, 'in_progress')
                    
                    apk_results = mongodb_client.get_apk_results(scan_id)
                    if not apk_results:
                         logger.error(f"APK results not found for {scan_id}")
                         continue
                         
                    results_data = apk_results.get('results', apk_results)
                    decompiled_path = results_data.get('decompiled_path')
                    
                    if decompiled_path and decompiled_path.startswith(APK_SCANNER_PATH):
                         decompiled_path = decompiled_path.replace(APK_SCANNER_PATH, APK_INPUT_PATH)
                    
                    if decompiled_path and os.path.exists(decompiled_path):
                         try:
                             report = perform_secret_scan(scan_id, decompiled_path)
                             secrets = report.get('findings', [])
                             summary = report.get('summary', {})
                             mongodb_client.save_secret_results(scan_id, secrets, summary)
                             mongodb_client.update_scan_stage(scan_id, 'completed')
                             logger.info(f"✅ Secret scan completed for {scan_id}")
                         except Exception as scan_err:
                             logger.error(f"Scan failed: {scan_err}")
                             mongodb_client.update_scan_stage(scan_id, 'failed')
                    else:
                         logger.error(f"Path not found: {decompiled_path}")
            except Exception as e:
                logger.error(f"Error in Kafka loop: {e}")
                
    except Exception as e:
        logger.error(f"Failed to start consumer: {e}")

# Start the consumer
threading.Thread(target=kafka_consumer_thread, daemon=True).start()


if __name__ == '__main__':
    logger.info("Starting SecretHunter service...")
    
    # Connect to MongoDB
    if not mongodb_client.connect():
        logger.warning("MongoDB connection failed, will retry on first request")
    
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Server starting on port {port}")
    logger.info(f"Swagger UI: http://localhost:{port}/swagger/")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
