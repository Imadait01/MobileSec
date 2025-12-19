"""
NetworkInspector - Microservice Flask pour l'analyse du trafic réseau Android

Ce service permet de :
- Lancer un émulateur Android dans Docker
- Installer et exécuter des APK
- Capturer le trafic réseau via mitmproxy
- Analyser les problèmes de sécurité réseau
- Générer des rapports détaillés

API Documentation: /swagger/
Lit depuis MongoDB (apk_results), écrit dans MongoDB (network_results)
"""
import os
import os
import sys
import json
import logging
import subprocess
import threading
from datetime import datetime
import time
from pathlib import Path

try:
    from confluent_kafka import Consumer
except ImportError:
    Consumer = None
    print("!!! confluent_kafka import failed !!!", flush=True)

print(f"!!! Consumer available: {Consumer is not None} !!!", flush=True)

# --- Kafka consumer for orchestration ---
def kafka_consumer_thread():
    if Consumer is None:
        print("confluent_kafka n'est pas installé. Kafka consumer désactivé.")
        return
    conf = {
        'bootstrap.servers': os.getenv('KAFKA_BROKERS', 'kafka:9092'),
        'group.id': 'network-inspector-group',
        'auto.offset.reset': 'earliest'
    }
    consumer = Consumer(conf)
    print("Consumer created. Subscribing...", flush=True)
    consumer.subscribe(['scan-requests'])
    print("Subscribed. Starting poll loop...", flush=True)
    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            print(f"Kafka error: {msg.error()}", flush=True)
            continue
        print(f"Message received: {msg.value()}", flush=True)
        data = json.loads(msg.value().decode('utf-8'))
        scan_id = data.get('id')
        if scan_id:
            print(f"[Kafka] Received scan request for scan_id: {scan_id}")
            apk_filename = data.get('apk_path')
            
            # Ensure we only have the filename
            apk_filename = os.path.basename(apk_filename)
            
            # Construct path to the shared volume
            # network-inspector sees it at /app/shared_uploads/{filename}
            apk_path = os.path.join('/app/shared_uploads', apk_filename)
            
            # Wait for file to be available (Shared Volume sync delay)
            retries = 5
            while not os.path.exists(apk_path) and retries > 0:
                print(f"[Kafka] Waiting for file {apk_path} to appear... ({retries})", flush=True)
                time.sleep(1)
                retries -= 1
            
            if os.path.exists(apk_path):
                print(f"[Kafka] Starting analysis for {apk_path}")
                # Trigger existing scan logic
                # Duration default is 60s, package_name empty for now (auto-detected or static)
                try:
                    # Run in a separate thread/process managed by the async wrapper, 
                    # but here we just call the wrapper function or start a thread.
                    # reusing perform_network_scan_async logic manually
                    scan_thread = threading.Thread(
                        target=perform_network_scan_async,
                        args=(apk_path, scan_id, 60, '')
                    )
                    scan_thread.start()
                except Exception as e:
                    print(f"[Kafka] Error triggering scan: {e}")
            else:
                print(f"[Kafka] Error: APK file not found at {apk_path}. Check volume mounts.")

# Démarre le consommateur dans un thread séparé
threading.Thread(target=kafka_consumer_thread, daemon=True).start()
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger
from werkzeug.utils import secure_filename

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.emulator_manager import EmulatorManager
from utils.traffic_analyzer import TrafficAnalyzer
from database.mongodb_client import mongodb_client

# Configuration
UPLOAD_FOLDER = 'uploads'
CAPTURES_FOLDER = 'captures'
ALLOWED_EXTENSIONS = {'apk', 'aab'}
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
PROXY_PORT = 8080
SCAN_DURATION = 60  # Durée par défaut du scan en secondes

# Mode émulateur externe: quand vrai, le service ne gère pas l'AVD
EXTERNAL_EMULATOR_MODE = os.environ.get('EXTERNAL_EMULATOR_MODE', 'false').lower() == 'true'

# Token de sécurité interne (doit être identique dans APKScanner)
INTERNAL_API_TOKEN = os.environ.get('INTERNAL_API_TOKEN', 'network-inspector-internal-token-2024')
ALLOWED_CALLERS = ['apk-scanner']  # Seul APKScanner peut appeler ce service

# Créer les dossiers nécessaires
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(CAPTURES_FOLDER).mkdir(exist_ok=True)
Path('logs').mkdir(exist_ok=True)

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/network_inspector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialisation Flask
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
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
        "title": "NetworkInspector API",
        "description": "API pour l'analyse du trafic réseau Android. Lit depuis MongoDB (apk_results), écrit dans MongoDB (network_results).",
        "version": "2.0.0",
        "contact": {"name": "Security Platform Team"}
    },
    "basePath": "/",
    "schemes": ["http", "https"],
    "tags": [
        {"name": "Health", "description": "Endpoints de santé"},
        {"name": "Scan", "description": "Endpoints de scan réseau"},
        {"name": "Results", "description": "Endpoints de résultats"},
        {"name": "Statistics", "description": "Endpoints de statistiques"}
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# État global du scan
scan_status = {
    'is_scanning': False,
    'current_scan_id': None,
    'progress': 0,
    'message': 'Ready'
}


def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def require_internal_auth(f):
    """
    Décorateur pour vérifier l'authentification interne
    Seul APKScanner peut appeler ces endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Récupérer le token depuis le header
        token = request.headers.get('X-Internal-Token')
        
        if not token:
            logger.warning(f"Unauthorized access attempt to {request.path} - No token provided")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'This endpoint is only accessible by APKScanner service'
            }), 401
        
        if token != INTERNAL_API_TOKEN:
            logger.warning(f"Unauthorized access attempt to {request.path} - Invalid token")
            return jsonify({
                'error': 'Forbidden',
                'message': 'Invalid authentication token'
            }), 403
        
        # Vérifier le caller (optionnel - via header custom)
        caller = request.headers.get('X-Caller-Service', 'unknown')
        if caller not in ALLOWED_CALLERS:
            logger.warning(f"Unauthorized caller: {caller}")
            return jsonify({
                'error': 'Forbidden',
                'message': f'Service {caller} is not authorized to call this endpoint'
            }), 403
        
        logger.info(f"Authorized call from {caller} to {request.path}")
        return f(*args, **kwargs)
    
    return decorated_function


def start_mitmproxy(capture_file, duration=60):
    """
    Lance mitmproxy en mode script pour capturer le trafic
    
    Args:
        capture_file (str): Fichier de sortie pour les captures
        duration (int): Durée de capture en secondes
    """
    try:
        logger.info(f"Starting mitmproxy on port {PROXY_PORT}")
        
        # Configurer l'addon avec le fichier de sortie
        addon_script = os.path.join('src', 'proxy', 'addon.py')
        
        # Commande mitmproxy
        cmd = [
            'mitmdump',
            '-p', str(PROXY_PORT),
            '-s', addon_script,
            '--set', f'output_file={capture_file}',
            '--ssl-insecure'  # Accepter les certificats auto-signés
        ]
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        # Lancer mitmproxy dans un processus séparé
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Attendre la durée spécifiée
        time.sleep(duration)
        
        # Arrêter mitmproxy
        process.terminate()
        process.wait(timeout=10)
        
        logger.info("mitmproxy stopped")
        return True
        
    except Exception as e:
        logger.error(f"Error running mitmproxy: {e}")
        return False


def perform_network_scan(apk_path, scan_id, duration=60, package_name=''):
    """
    Effectue un scan réseau complet
    
    Args:
        apk_path (str): Chemin vers l'APK
        scan_id (str): ID unique du scan
        duration (int): Durée du scan
    """
    global scan_status
    
    try:
        scan_status['is_scanning'] = True
        scan_status['current_scan_id'] = scan_id
        scan_status['progress'] = 0
        scan_status['message'] = 'Initializing...'
        
        capture_file = os.path.join(CAPTURES_FOLDER, f'{scan_id}_traffic.json')
        report_file = os.path.join(CAPTURES_FOLDER, f'{scan_id}_report.json')
        
        # Flag pour savoir si l'analyse dynamique a réussi
        dynamic_analysis_success = False
        mitm_proxy_success = False
        
        try:
            if not EXTERNAL_EMULATOR_MODE:
                # Étape 1: Vérifier Docker
                scan_status['progress'] = 10
                scan_status['message'] = 'Checking Docker...'
                logger.info("Step 1: Checking Docker")

                emulator = EmulatorManager(container_name=f'android-{scan_id}')
                if not emulator.check_docker():
                    raise Exception("Docker is not available")

                # Étape 2: Démarrer l'émulateur
                scan_status['progress'] = 20
                scan_status['message'] = 'Starting Android emulator...'
                logger.info("Step 2: Starting emulator")

                if not emulator.start_emulator(proxy_host='host.docker.internal', proxy_port=PROXY_PORT):
                    raise Exception("Failed to start emulator")

                # Étape 3: Installer l'APK
                scan_status['progress'] = 40
                scan_status['message'] = 'Installing APK...'
                logger.info("Step 3: Installing APK")

                if not emulator.install_apk(apk_path):
                    raise Exception("Failed to install APK")

                # Extraire le nom du package (simplifié - normalement il faudrait parser le manifest)
                package_name = 'com.example.app'  # À remplacer par une extraction réelle

                # Étape 4: Lancer l'application
                scan_status['progress'] = 50
                scan_status['message'] = 'Launching application...'
                logger.info("Step 4: Launching application")

                emulator.launch_app(package_name)
            else:
                # Mode émulateur externe
                scan_status['progress'] = 20
                scan_status['message'] = 'External AVD mode...'
                logger.info("External emulator mode enabled.")
            
            # Étape 5: Démarrer mitmproxy et capturer le trafic
            scan_status['progress'] = 60
            scan_status['message'] = 'Capturing network traffic...'
            logger.info("Step 5: Capturing traffic")
            
            if not EXTERNAL_EMULATOR_MODE:
                # Mode interne: lancer mitmproxy temporaire
                proxy_thread = threading.Thread(
                    target=start_mitmproxy,
                    args=(capture_file, duration)
                )
                proxy_thread.start()
                time.sleep(5)
                emulator.interact_with_app(duration=duration - 10)
                proxy_thread.join()
            else:
                # ... existing external logic ...
                logger.info(f"External mode: persistent proxy already capturing. Scan duration: {duration}s")
                time.sleep(duration)
                
                persistent_capture_file = os.path.join(CAPTURES_FOLDER, 'traffic.json')
                if os.path.exists(persistent_capture_file):
                    import shutil
                    shutil.copy(persistent_capture_file, capture_file)
                    logger.info(f"Using persistent capture file: {persistent_capture_file}")
                else:
                    logger.warning(f"Persistent capture file not found: {persistent_capture_file}")
                    # Créer un fichier vide pour éviter les erreurs
                    with open(capture_file, 'w') as f:
                        json.dump({'flows': [], 'summary': {'total_flows': 0}}, f)
                logger.info(f"Scan capture saved: {capture_file}")
            
            dynamic_analysis_success = True
            mitm_proxy_success = True

        except Exception as emulator_error:
            logger.error(f"Emulator/Dynamic Analysis failed: {emulator_error}")
            scan_status['message'] = f'Dynamic analysis skipped: {str(emulator_error)}'
            # Create empty capture file if it failed
            if not os.path.exists(capture_file):
                 with open(capture_file, 'w') as f:
                    json.dump({'flows': [], 'summary': {'total_flows': 0, 'error': str(emulator_error)}}, f)
        
        # Étape 6: Analyser le trafic (Même si vide)
        scan_status['progress'] = 80
        scan_status['message'] = 'Analyzing traffic...'
        logger.info("Step 6: Analyzing traffic")
        
        analyzer = TrafficAnalyzer(capture_file)
        analysis_result = analyzer.analyze()
        if not dynamic_analysis_success:
             analysis_result['warnings'] = ["Dynamic analysis failed (Emulator/Proxy issue). Results are based on empty capture."]
        
        analyzer.export_report(report_file)
        
        # Étape 7: Nettoyer
        scan_status['progress'] = 90
        scan_status['message'] = 'Cleaning up...'
        logger.info("Step 7: Cleaning up")
        
        if not EXTERNAL_EMULATOR_MODE:
            try:
                emulator.stop_emulator()
            except:
                pass
        
        # Nettoyer le fichier APK
        # DO NOT REMOVE IF SHARED! But here we are consumption endpoint?
        # NetworkInspector gets file from shared volume. It should NOT delete it 
        # unless it knows no one else needs it. 
        # But safest is to leave it since apk-scanner manages lifecycle (or should).
        # try:
        #    os.remove(apk_path)
        # except Exception:
        #    pass
        
        # Finaliser
        scan_status['progress'] = 100
        scan_status['message'] = 'Completed'
        scan_status['is_scanning'] = False
        
        logger.info(f"Scan {scan_id} completed successfully (Dynamic: {dynamic_analysis_success})")
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'capture_file': capture_file,
            'report_file': report_file,
            'analysis': analysis_result
        }
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        
        # Nettoyer en cas d'erreur
        try:
            emulator.stop_emulator()
        except Exception:
            pass
        
        scan_status['is_scanning'] = False
        scan_status['message'] = f'Failed: {str(e)}'
        
        return {
            'status': 'failed',
            'error': str(e),
            'scan_id': scan_id
        }


# ============= ROUTES API =============

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
        'service': 'NetworkInspector',
        'version': '2.0.0',
        'description': 'Android Network Traffic Analysis Service',
        'swagger': '/swagger/',
        'mongodb_connected': mongodb_client.is_connected(),
        'external_emulator_mode': EXTERNAL_EMULATOR_MODE,
        'proxy_port': PROXY_PORT
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
        'service': 'NetworkInspector',
        'scanning': scan_status['is_scanning'],
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Alias for health check compatible with Gateway"""
    return health_check()


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyser le trafic réseau d'un APK (appelé par APK-Scanner)
    ---
    tags:
      - Scan
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
            duration:
              type: integer
              default: 60
              description: Durée du scan en secondes (ignoré en mode statique)
    responses:
      200:
        description: Analyse terminée
      400:
        description: Paramètres manquants
      404:
        description: Résultats APK non trouvés
      409:
        description: Un autre scan est en cours
    """
    import datetime
    try:
        from utils.static_analyzer import StaticNetworkAnalyzer

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
        if decompiled_path and decompiled_path.startswith('/app/decompiled'):
            decompiled_path = decompiled_path.replace('/app/decompiled', '/app/apk-input')
            logger.info(f"Remapped path to: {decompiled_path}")

        if not decompiled_path or not os.path.exists(decompiled_path):
            mongodb_client.update_scan_stage(scan_id, 'failed')
            return jsonify({'error': f'Decompiled path not found: {decompiled_path}'}), 404

        # Perform static analysis
        analyzer = StaticNetworkAnalyzer()
        issues = analyzer.analyze_directory(decompiled_path)
        report = analyzer.generate_report()
            
        # Prepare analysis data for MongoDB
        analysis_data = {
            'security_issues': issues,
            'endpoints': [],  # Static analysis doesn't capture runtime endpoints
            'summary': report
        }

        # Save results to MongoDB
        mongodb_client.save_network_results(scan_id, analysis_data)
        mongodb_client.update_scan_stage(scan_id, 'completed')

        logger.info(f"✅ Network analysis completed for {scan_id}: {len(issues)} issues found")

        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'issues_found': len(issues),
            'summary': report.get('severity_breakdown', {})
        })
            
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {e}", exc_info=True)
        if scan_id:
            mongodb_client.update_scan_stage(scan_id, 'failed')
        return jsonify({'error': str(e)}), 500


def perform_network_scan_async(apk_path, scan_id, duration, package_name):
    """Wrapper async pour perform_network_scan avec sauvegarde MongoDB"""
    result = perform_network_scan(apk_path, scan_id, duration, package_name)
    
    # Sauvegarder dans MongoDB
    if result.get('status') == 'completed':
        # Fetch existing results to preserve Static Analysis data (security_issues)
        existing_results = mongodb_client.get_network_results(scan_id)
        
        final_analysis = result.get('analysis', {})
        if existing_results and 'analysis' in existing_results:
            # Merge: Keep existing static issues, override/add dynamic fields
            existing_analysis = existing_results['analysis']
            # Ensure we don't lose security_issues
            if 'security_issues' in existing_analysis:
                final_analysis['security_issues'] = existing_analysis['security_issues']
            if 'summary' in existing_analysis and 'severity_breakdown' in existing_analysis['summary']:
                 # Merge summaries if needed, or just prioritize one. Static summary is important.
                 pass 

            # Recursive update or simple merge? 
            # Static has: security_issues, endpoints, summary
            # Dynamic has: capture_summary, data_leaks_analysis, etc.
            # They have disjoint keys mostly.
            existing_analysis.update(final_analysis)
            final_analysis = existing_analysis

        mongodb_client.save_network_results(
            scan_id, 
            final_analysis,
            result
        )
        mongodb_client.update_scan_stage(scan_id, 'completed')
        logger.info(f"✅ Network scan completed for {scan_id}")
    else:
        mongodb_client.update_scan_stage(scan_id, 'failed')
        logger.error(f"❌ Network scan failed for {scan_id}")


@app.route('/run-network-scan', methods=['POST'])
@require_internal_auth
def run_network_scan():
    """
    Endpoint principal pour lancer un scan réseau (legacy)
    ---
    tags:
      - Scan
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: Fichier APK à analyser
      - name: duration
        in: formData
        type: integer
        required: false
        default: 60
      - name: package_name
        in: formData
        type: string
        required: false
    responses:
      202:
        description: Scan démarré
      400:
        description: Paramètres invalides
      409:
        description: Un autre scan est en cours
    """
    try:
        # Vérifier qu'aucun scan n'est en cours
        if scan_status['is_scanning']:
            return jsonify({
                'error': 'Another scan is already in progress',
                'current_scan_id': scan_status['current_scan_id']
            }), 409
        
        # Vérifier qu'un fichier est présent
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only APK and AAB files are allowed'}), 400
        
        # Récupérer la durée du scan
        duration = request.form.get('duration', SCAN_DURATION, type=int)
        duration = min(max(duration, 30), 300)  # Entre 30 et 300 secondes
        
        # Récupérer le nom du package (en mode externe)
        package_name = request.form.get('package_name', '')
        
        # Sauvegarder le fichier
        filename = secure_filename(file.filename)
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        logger.info(f"File uploaded: {filepath}")
        
        # Lancer le scan dans un thread séparé
        scan_thread = threading.Thread(
            target=perform_network_scan,
            args=(filepath, scan_id, duration, package_name)
        )
        scan_thread.start()
        
        # Attendre un peu pour obtenir le statut initial
        time.sleep(2)
        
        return jsonify({
            'message': 'Network scan started',
            'scan_id': scan_id,
            'duration': duration,
            'status': scan_status
        }), 202
        
    except Exception as e:
        logger.error(f"Error in run-network-scan endpoint: {e}", exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/scan-status', methods=['GET'])
def get_scan_status():
    """
    Récupère le statut du scan en cours
    ---
    tags:
      - Scan
    responses:
      200:
        description: Statut du scan
    """
    return jsonify(scan_status)


@app.route('/api/scan-status', methods=['GET'])
def api_get_scan_status():
    """Alias compatible API Gateway"""
    return get_scan_status()


@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    """
    Récupérer les résultats de l'analyse réseau par ID
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
        description: Résultats de l'analyse
      404:
        description: Résultats non trouvés
    """
    try:
        results = mongodb_client.get_network_results(scan_id)
        
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
    Lister tous les résultats d'analyse réseau
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
        results = mongodb_client.get_all_network_results(limit)
        
        for r in results:
            r['_id'] = str(r.get('_id', ''))
        
        return jsonify({'count': len(results), 'results': results})
        
    except Exception as e:
        logger.error(f"Error listing results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/results/<scan_id>', methods=['DELETE'])
def delete_results(scan_id):
    """
    Supprimer les résultats d'analyse
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
        deleted = mongodb_client.delete_network_results(scan_id)
        
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


@app.route('/analysis/<scan_id>', methods=['GET'])
@require_internal_auth
def get_analysis(scan_id):
    """
    Récupère les résultats d'analyse pour un scan
    SÉCURISÉ: Accessible uniquement par APKScanner
    
    Args:
        scan_id (str): ID du scan
    """
    try:
        report_file = os.path.join(CAPTURES_FOLDER, f'{scan_id}_report.json')
        
        if not os.path.exists(report_file):
            return jsonify({'error': 'Analysis not found'}), 404
        
        import json
        with open(report_file, 'r') as f:
            analysis = json.load(f)
        
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Error getting analysis: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/captures/<scan_id>', methods=['GET'])
@require_internal_auth
def get_capture(scan_id):
    """
    Récupère les données de capture brutes
    SÉCURISÉ: Accessible uniquement par APKScanner
    
    Args:
        scan_id (str): ID du scan
    """
    try:
        capture_file = os.path.join(CAPTURES_FOLDER, f'{scan_id}_traffic.json')
        
        if not os.path.exists(capture_file):
            return jsonify({'error': 'Capture not found'}), 404
        
        import json
        with open(capture_file, 'r') as f:
            capture = json.load(f)
        
        return jsonify(capture)
        
    except Exception as e:
        logger.error(f"Error getting capture: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/scans', methods=['GET'])
def list_scans():
    """Liste tous les scans disponibles"""
    try:
        scans = []
        
        for file in os.listdir(CAPTURES_FOLDER):
            if file.endswith('_report.json'):
                scan_id = file.replace('_report.json', '')
                scans.append({
                    'scan_id': scan_id,
                    'report_file': file
                })
        
        return jsonify({
            'count': len(scans),
            'scans': sorted(scans, key=lambda x: x['scan_id'], reverse=True)
        })
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Gestion des erreurs
@app.errorhandler(413)
def request_entity_too_large(error):
    """Fichier trop volumineux"""
    return jsonify({
        'error': 'File too large',
        'max_size': f'{MAX_FILE_SIZE // (1024*1024)} MB'
    }), 413


@app.errorhandler(404)
def not_found(error):
    """Route non trouvée"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Erreur interne"""
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting NetworkInspector service...")
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    logger.info(f"Captures folder: {CAPTURES_FOLDER}")
    logger.info(f"Proxy port: {PROXY_PORT}")
    logger.info(f"External emulator mode: {EXTERNAL_EMULATOR_MODE}")
    
    # En mode émulateur externe, démarrer mitmproxy immédiatement et le laisser écouter
    if EXTERNAL_EMULATOR_MODE:
        logger.info("External emulator mode enabled - starting persistent mitmproxy")
        
        def run_persistent_proxy():
            """Lance mitmproxy en mode persistant pour mode émulateur externe"""
            try:
                addon_path = os.path.join(os.path.dirname(__file__), 'proxy', 'addon.py')
                cmd = [
                    'mitmdump',
                    '--listen-port', str(PROXY_PORT),
                    '--set', 'block_global=false',
                    '--set', 'upstream_cert=false',
                    '-s', addon_path
                ]
                logger.info(f"Starting persistent mitmproxy: {' '.join(cmd)}")
                subprocess.run(cmd, check=True)
            except Exception as e:
                logger.error(f"Error running persistent mitmproxy: {e}")
        
        # Lancer mitmproxy dans un thread daemon
        proxy_thread = threading.Thread(target=run_persistent_proxy, daemon=True)
        proxy_thread.start()
        logger.info("Persistent mitmproxy thread started")
        time.sleep(2)  # Attendre que mitmproxy démarre
    
    # Démarrer le serveur
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Connect to MongoDB
    if not mongodb_client.connect():
        logger.warning("MongoDB connection failed, will retry on first request")
    
    logger.info(f"Server starting on port {port}")
    logger.info(f"Swagger UI: http://localhost:{port}/swagger/")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
    )
