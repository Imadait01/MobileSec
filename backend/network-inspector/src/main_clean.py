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
# ...existing code up to Flask app initialization...
import os
import sys
import json
import logging
import subprocess
import threading
from datetime import datetime
import time
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.emulator_manager import EmulatorManager
from utils.traffic_analyzer import TrafficAnalyzer
from database.mongodb_client import mongodb_client

UPLOAD_FOLDER = 'uploads'
CAPTURES_FOLDER = 'captures'
ALLOWED_EXTENSIONS = {'apk', 'aab'}
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
PROXY_PORT = 8080
SCAN_DURATION = 60
EXTERNAL_EMULATOR_MODE = os.environ.get('EXTERNAL_EMULATOR_MODE', 'false').lower() == 'true'
INTERNAL_API_TOKEN = os.environ.get('INTERNAL_API_TOKEN', 'network-inspector-internal-token-2024')
ALLOWED_CALLERS = ['apk-scanner']
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(CAPTURES_FOLDER).mkdir(exist_ok=True)
Path('logs').mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/network_inspector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
CORS(app)

# ...existing code for swagger, scan_status, utils, etc...

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
        'scanning': False,
        'timestamp': datetime.now().isoformat()
    })

# ...existing code for all other routes and logic...
