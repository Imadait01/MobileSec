"""
Addon mitmproxy pour capturer et analyser le trafic réseau Android

Ce module s'intègre avec mitmproxy pour intercepter et analyser :
- Requêtes HTTP/HTTPS
- Certificats TLS
- Cookies et headers sensibles
- Fuites de données (emails, tokens, mots de passe)
"""
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from mitmproxy import http, ctx
from typing import Dict, List, Any


class NetworkInterceptor:
    """Addon mitmproxy pour l'interception du trafic réseau"""
    
    def __init__(self, output_file='captures/traffic.json'):
        """
        Initialise l'interceptor
        
        Args:
            output_file (str): Fichier de sortie pour les captures
        """
        self.output_file = output_file
        self.captured_flows = []
        self.tls_issues = []
        self.plaintext_traffic = []
        self.sensitive_data_leaks = []
        self.insecure_endpoints = []
        self.last_export_time = datetime.now()
        self.export_interval = 10  # Export toutes les 10 secondes
        
        # Patterns pour détecter les données sensibles
        self.sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'api_key': r'(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)[\"\']?\s*[:=]\s*[\"\']?([a-zA-Z0-9_\-]{20,})',
            'password': r'(?i)(password|passwd|pwd)[\"\']?\s*[:=]\s*[\"\']?([^\s\"\']{6,})',
            'bearer_token': r'Bearer\s+[a-zA-Z0-9\-._~+/]+',
            'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        }
        
        # Headers sensibles à surveiller
        self.sensitive_headers = [
            'authorization',
            'cookie',
            'set-cookie',
            'x-api-key',
            'x-auth-token',
            'x-access-token',
        ]
        
        self.logger = logging.getLogger(__name__)
    
    def export_current_state(self):
        """
        Exporte l'état actuel des captures (appelé périodiquement)
        """
        try:
            # Créer le répertoire de sortie si nécessaire
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
            
            # Compiler le rapport complet
            report = {
                'scan_timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_flows': len(self.captured_flows),
                    'tls_issues_count': len(self.tls_issues),
                    'plaintext_traffic_count': len(self.plaintext_traffic),
                    'sensitive_leaks_count': len(self.sensitive_data_leaks),
                    'insecure_endpoints_count': len(self.insecure_endpoints)
                },
                'flows': self.captured_flows,
                'tls_issues': self.tls_issues,
                'plaintext_traffic': self.plaintext_traffic,
                'sensitive_data_leaks': self.sensitive_data_leaks,
                'insecure_endpoints': self.insecure_endpoints
            }
            
            # Sauvegarder en JSON
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.debug(f"Exported {len(self.captured_flows)} flows to {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting state: {e}")
        
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Capture et analyse les requêtes HTTP/HTTPS
        
        Args:
            flow: Flow mitmproxy
        """
        try:
            request_data = {
                'timestamp': datetime.now().isoformat(),
                'type': 'request',
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'host': flow.request.host,
                'port': flow.request.port,
                'scheme': flow.request.scheme,
                'path': flow.request.path,
                'headers': dict(flow.request.headers),
                'content_length': len(flow.request.content) if flow.request.content else 0,
            }
            
            # Vérifier si HTTPS
            is_secure = flow.request.scheme == 'https'
            request_data['is_secure'] = is_secure
            
            # Détecter le trafic en clair
            if not is_secure:
                self.plaintext_traffic.append({
                    'url': flow.request.pretty_url,
                    'method': flow.request.method,
                    'timestamp': request_data['timestamp']
                })
                self.logger.warning(f"Plaintext traffic detected: {flow.request.pretty_url}")
            
            # Analyser le corps de la requête
            if flow.request.content:
                try:
                    content = flow.request.content.decode('utf-8', errors='ignore')
                    request_data['body_preview'] = content[:500]  # Limiter la taille
                    
                    # Rechercher des données sensibles
                    self._detect_sensitive_data(content, flow.request.pretty_url, 'request_body')
                    
                except Exception as e:
                    self.logger.debug(f"Could not decode request content: {e}")
            
            # Analyser les headers
            self._analyze_headers(flow.request.headers, flow.request.pretty_url, 'request')
            
            # Analyser les paramètres de l'URL
            if '?' in flow.request.path:
                query_string = flow.request.path.split('?', 1)[1]
                self._detect_sensitive_data(query_string, flow.request.pretty_url, 'query_params')
            
            self.captured_flows.append(request_data)
            
            # Vérifier si l'intervalle d'export est écoulé
            if (datetime.now() - self.last_export_time).total_seconds() >= self.export_interval:
                self.export_current_state()
                self.last_export_time = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Capture et analyse les réponses HTTP/HTTPS
        
        Args:
            flow: Flow mitmproxy
        """
        try:
            response_data = {
                'timestamp': datetime.now().isoformat(),
                'type': 'response',
                'url': flow.request.pretty_url,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'content_length': len(flow.response.content) if flow.response.content else 0,
                'content_type': flow.response.headers.get('content-type', 'unknown'),
            }
            
            # Analyser les cookies
            if 'set-cookie' in flow.response.headers:
                cookies = flow.response.headers.get_all('set-cookie')
                response_data['cookies'] = cookies
                self._analyze_cookies(cookies, flow.request.pretty_url)
            
            # Analyser le corps de la réponse
            if flow.response.content:
                try:
                    content = flow.response.content.decode('utf-8', errors='ignore')
                    response_data['body_preview'] = content[:500]
                    
                    # Rechercher des données sensibles
                    self._detect_sensitive_data(content, flow.request.pretty_url, 'response_body')
                    
                except Exception as e:
                    self.logger.debug(f"Could not decode response content: {e}")
            
            # Analyser les headers de sécurité
            self._analyze_security_headers(flow.response.headers, flow.request.pretty_url)
            
            self.captured_flows.append(response_data)
            
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")
    
    def tls_start_client(self, data) -> None:
        """
        Analyse le démarrage de la connexion TLS
        
        Args:
            data: Données TLS
        """
        try:
            host = data.context.server.address[0] if data.context.server.address else 'unknown'
            port = data.context.server.address[1] if data.context.server.address else 0
            
            self.logger.info(f"TLS connection started: {data.context.server.address}")
            
            # Enregistrer la tentative de connexion TLS
            tls_attempt = {
                'timestamp': datetime.now().isoformat(),
                'type': 'tls_connection_attempt',
                'host': host,
                'port': port,
                'url': f"https://{host}:{port}" if port != 443 else f"https://{host}"
            }
            self.captured_flows.append(tls_attempt)
            
            # Vérifier si l'intervalle d'export est écoulé
            if (datetime.now() - self.last_export_time).total_seconds() >= self.export_interval:
                self.export_current_state()
                self.last_export_time = datetime.now()
                
        except Exception as e:
            self.logger.debug(f"Error in tls_start_client: {e}")
    
    def tls_established_client(self, data) -> None:
        """
        Analyse la connexion TLS établie
        
        Args:
            data: Données TLS
        """
        try:
            conn = data.context.client.tls_established
            if conn:
                tls_info = {
                    'timestamp': datetime.now().isoformat(),
                    'host': data.context.server.address[0],
                    'port': data.context.server.address[1],
                    'tls_version': data.context.client.tls_version if hasattr(data.context.client, 'tls_version') else 'unknown',
                    'cipher': data.context.client.cipher if hasattr(data.context.client, 'cipher') else 'unknown',
                }
                
                # Vérifier la version TLS
                if hasattr(data.context.client, 'tls_version'):
                    tls_version = data.context.client.tls_version
                    if tls_version in ['TLSv1.0', 'TLSv1.1', 'SSLv3']:
                        self.tls_issues.append({
                            'type': 'outdated_tls_version',
                            'severity': 'HIGH',
                            'host': tls_info['host'],
                            'version': tls_version,
                            'message': f'Outdated TLS version: {tls_version}'
                        })
                        self.logger.warning(f"Outdated TLS version detected: {tls_version} for {tls_info['host']}")
                
                self.captured_flows.append(tls_info)
                
        except Exception as e:
            self.logger.debug(f"Error in tls_established_client: {e}")
    
    def _detect_sensitive_data(self, content: str, url: str, location: str) -> None:
        """
        Détecte les données sensibles dans le contenu
        
        Args:
            content (str): Contenu à analyser
            url (str): URL source
            location (str): Emplacement (request_body, response_body, etc.)
        """
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Masquer partiellement les données sensibles
                masked_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[-1]  # Prendre la dernière capture du groupe
                    if len(str(match)) > 10:
                        masked = str(match)[:4] + '***' + str(match)[-4:]
                    else:
                        masked = '***'
                    masked_matches.append(masked)
                
                leak = {
                    'type': data_type,
                    'location': location,
                    'url': url,
                    'count': len(matches),
                    'samples': masked_matches[:3],  # Limiter à 3 exemples
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH' if data_type in ['password', 'credit_card', 'ssn'] else 'MEDIUM'
                }
                
                self.sensitive_data_leaks.append(leak)
                self.logger.warning(f"Sensitive data leak detected: {data_type} in {location} for {url}")
    
    def _analyze_headers(self, headers: Dict, url: str, header_type: str) -> None:
        """
        Analyse les headers sensibles
        
        Args:
            headers (Dict): Headers HTTP
            url (str): URL
            header_type (str): Type (request/response)
        """
        for header_name in self.sensitive_headers:
            if header_name in headers:
                value = headers[header_name]
                
                # Masquer la valeur
                if len(value) > 20:
                    masked_value = value[:10] + '***' + value[-10:]
                else:
                    masked_value = '***'
                
                leak = {
                    'type': f'sensitive_header_{header_name}',
                    'location': f'{header_type}_headers',
                    'url': url,
                    'header_name': header_name,
                    'value_preview': masked_value,
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'MEDIUM'
                }
                
                self.sensitive_data_leaks.append(leak)
    
    def _analyze_cookies(self, cookies: List[str], url: str) -> None:
        """
        Analyse les cookies pour détecter les problèmes de sécurité
        
        Args:
            cookies (List[str]): Liste des cookies
            url (str): URL
        """
        for cookie in cookies:
            cookie_lower = cookie.lower()
            
            # Vérifier les flags de sécurité
            issues = []
            
            if 'secure' not in cookie_lower:
                issues.append('Missing Secure flag')
            
            if 'httponly' not in cookie_lower:
                issues.append('Missing HttpOnly flag')
            
            if 'samesite' not in cookie_lower:
                issues.append('Missing SameSite attribute')
            
            if issues:
                self.tls_issues.append({
                    'type': 'insecure_cookie',
                    'severity': 'MEDIUM',
                    'url': url,
                    'issues': issues,
                    'timestamp': datetime.now().isoformat()
                })
    
    def _analyze_security_headers(self, headers: Dict, url: str) -> None:
        """
        Analyse les headers de sécurité manquants
        
        Args:
            headers (Dict): Headers HTTP
            url (str): URL
        """
        security_headers = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection',
            'content-security-policy',
        ]
        
        missing_headers = []
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            self.tls_issues.append({
                'type': 'missing_security_headers',
                'severity': 'LOW',
                'url': url,
                'missing_headers': missing_headers,
                'timestamp': datetime.now().isoformat()
            })
    
    def done(self) -> None:
        """
        Appelé à la fin de la capture - sauvegarde les résultats
        """
        try:
            # Créer le répertoire de sortie si nécessaire
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
            
            # Compiler le rapport complet
            report = {
                'scan_timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_flows': len(self.captured_flows),
                    'tls_issues_count': len(self.tls_issues),
                    'plaintext_traffic_count': len(self.plaintext_traffic),
                    'sensitive_leaks_count': len(self.sensitive_data_leaks),
                    'insecure_endpoints_count': len(self.insecure_endpoints)
                },
                'flows': self.captured_flows,
                'tls_issues': self.tls_issues,
                'plaintext_traffic': self.plaintext_traffic,
                'sensitive_data_leaks': self.sensitive_data_leaks,
                'insecure_endpoints': self.insecure_endpoints
            }
            
            # Sauvegarder en JSON
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Traffic capture saved to {self.output_file}")
            self.logger.info(f"Captured {len(self.captured_flows)} flows")
            self.logger.info(f"Found {len(self.tls_issues)} TLS issues")
            self.logger.info(f"Found {len(self.plaintext_traffic)} plaintext requests")
            self.logger.info(f"Found {len(self.sensitive_data_leaks)} sensitive data leaks")
            
        except Exception as e:
            self.logger.error(f"Error saving capture: {e}")


# Instance de l'addon pour mitmproxy
addons = [NetworkInterceptor()]
