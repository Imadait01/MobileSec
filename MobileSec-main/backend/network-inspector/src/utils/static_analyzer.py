"""
Static network analyzer - Analyse le code décompilé pour détecter les problèmes réseau
"""
import os
import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class StaticNetworkAnalyzer:
    """Analyse statique du code pour détecter les problèmes de sécurité réseau"""
    
    def __init__(self):
        self.issues = []
    
    def analyze_directory(self, directory_path):
        """Analyse un répertoire de code décompilé"""
        logger.info(f"Starting static network analysis of: {directory_path}")
        
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return []
        
        self.issues = []
        
        # Parcourir tous les fichiers
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(('.java', '.smali', '.xml')):
                    filepath = os.path.join(root, file)
                    self._analyze_file(filepath)
        
        logger.info(f"Static analysis completed: {len(self.issues)} issues found")
        return self.issues
    
    def _analyze_file(self, filepath):
        """Analyse un fichier pour détecter les problèmes réseau"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                relative_path = filepath
                
                # 1. URLs HTTP (non sécurisées)
                http_urls = re.findall(r'http://[^\s\'"<>]+', content, re.IGNORECASE)
                for url in http_urls:
                    self.issues.append({
                        'type': 'INSECURE_HTTP',
                        'severity': 'HIGH',
                        'file': relative_path,
                        'description': 'Insecure HTTP URL detected',
                        'detail': url,
                        'recommendation': 'Use HTTPS instead of HTTP'
                    })
                
                # 2. SSL/TLS désactivé
                ssl_patterns = [
                    (r'setHostnameVerifier.*ALLOW_ALL', 'SSL hostname verification disabled'),
                    (r'TrustAllCerts|trustAllHosts|X509TrustManager', 'Custom trust manager (potential bypass)'),
                    (r'setSSLSocketFactory.*null', 'SSL socket factory set to null'),
                ]
                
                for pattern, description in ssl_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.issues.append({
                            'type': 'SSL_BYPASS',
                            'severity': 'CRITICAL',
                            'file': relative_path,
                            'description': description,
                            'recommendation': 'Use proper SSL/TLS certificate validation'
                        })
                
                # 3. Network security config faible
                if 'cleartextTrafficPermitted="true"' in content:
                    self.issues.append({
                        'type': 'CLEARTEXT_TRAFFIC',
                        'severity': 'HIGH',
                        'file': relative_path,
                        'description': 'Cleartext traffic is permitted',
                        'recommendation': 'Disable cleartext traffic in network security config'
                    })
                
                # 4. WebView JavaScript activé (potentiel XSS)
                if 'setJavaScriptEnabled(true)' in content:
                    self.issues.append({
                        'type': 'WEBVIEW_JAVASCRIPT',
                        'severity': 'MEDIUM',
                        'file': relative_path,
                        'description': 'JavaScript enabled in WebView',
                        'recommendation': 'Only enable JavaScript if necessary and validate input'
                    })
                
                # 5. URLs privées/internes exposées
                internal_ips = re.findall(r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)', content)
                for ip in internal_ips:
                    self.issues.append({
                        'type': 'INTERNAL_IP',
                        'severity': 'LOW',
                        'file': relative_path,
                        'description': 'Internal IP address found',
                        'detail': ip,
                        'recommendation': 'Avoid hardcoding internal IPs'
                    })
        
        except Exception as e:
            logger.warning(f"Error analyzing file {filepath}: {e}")
    
    def generate_report(self):
        """Génère un rapport des problèmes trouvés"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        type_counts = {}
        
        for issue in self.issues:
            severity = issue.get('severity', 'LOW')
            issue_type = issue.get('type', 'UNKNOWN')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        
        return {
            'total_issues': len(self.issues),
            'severity_breakdown': severity_counts,
            'type_breakdown': type_counts,
            'issues': self.issues
        }
