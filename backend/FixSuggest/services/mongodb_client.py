"""
FixSuggest - Client MongoDB
============================
Récupère les vulnérabilités des 3 microservices de scan et stocke les suggestions.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from config import settings

logger = logging.getLogger(__name__)


class MongoDBClient:
    """
    Client MongoDB pour FixSuggest.
    Lit les résultats de CryptoCheck, SecretHunter, NetworkInspector.
    Stocke les suggestions générées.
    """
    
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self._connect()
    
    def _connect(self):
        """Établit la connexion à MongoDB"""
        try:
            self.client = MongoClient(settings.mongodb_uri)
            self.db = self.client[settings.mongodb_database]
            # Test de connexion
            self.client.admin.command('ping')
            logger.info(f"✅ Connecté à MongoDB: {settings.mongodb_database}")
        except ConnectionFailure as e:
            logger.error(f"❌ Erreur connexion MongoDB: {e}")
            self.client = None
            self.db = None
        except Exception as e:
            logger.error(f"❌ Erreur MongoDB: {e}")
            self.client = None
            self.db = None
    
    @property
    def is_connected(self) -> bool:
        return self.db is not None
    
    def get_crypto_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Récupère les vulnérabilités de CryptoCheck pour un scan.
        """
        if self.db is None:
            return []
        
        vulnerabilities = []
        
        try:
            # Chercher dans la collection crypto_results
            result = self.db.crypto_results.find_one({"scan_id": scan_id})
            
            # Structure réelle: vulnerabilities[] (pas findings)
            if result and result.get("vulnerabilities"):
                for idx, vuln in enumerate(result["vulnerabilities"]):
                    vulnerabilities.append({
                        "id": f"CRYPTO-{idx+1}",
                        "title": vuln.get("vulnerability") or vuln.get("type") or "Crypto Issue",
                        "description": vuln.get("message") or vuln.get("description") or "",
                        "severity": vuln.get("severity", "MEDIUM").upper(),
                        "file": vuln.get("file", "Unknown"),
                        "line": vuln.get("line"),
                        "code_snippet": vuln.get("code") or vuln.get("codeSnippet") or vuln.get("match"),
                        "cwe": vuln.get("cwe"),
                        "tool": "CryptoCheck",
                        "category": "cryptography"
                    })
            
            logger.info(f"📊 CryptoCheck: {len(vulnerabilities)} vulnérabilités pour scan {scan_id}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lecture CryptoCheck: {e}")
        
        return vulnerabilities
    
    def get_secret_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Récupère les secrets exposés de SecretHunter pour un scan.
        """
        if self.db is None:
            return []
        
        vulnerabilities = []
        
        try:
            # Chercher dans la collection secret_results
            result = self.db.secret_results.find_one({"scan_id": scan_id})
            
            # Structure réelle: secrets[] (pas findings)
            if result and result.get("secrets"):
                for idx, secret in enumerate(result["secrets"]):
                    secret_type = secret.get("type") or secret.get("rule_id") or "Secret"
                    vulnerabilities.append({
                        "id": f"SECRET-{idx+1}",
                        "title": f"Secret exposé: {secret_type}",
                        "description": secret.get("description") or f"Un secret de type '{secret_type}' a été détecté dans le code",
                        "severity": secret.get("severity", "HIGH").upper(),
                        "file": secret.get("file", "Unknown"),
                        "line": secret.get("line"),
                        "code_snippet": secret.get("match") or secret.get("secret"),
                        "tool": "SecretHunter",
                        "category": "secrets"
                    })
            
            logger.info(f"🔐 SecretHunter: {len(vulnerabilities)} secrets pour scan {scan_id}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lecture SecretHunter: {e}")
        
        return vulnerabilities
    
    def get_network_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Récupère les problèmes réseau de NetworkInspector pour un scan.
        """
        if self.db is None:
            return []
        
        vulnerabilities = []
        
        try:
            # Chercher dans la collection network_results
            result = self.db.network_results.find_one({"scan_id": scan_id})
            
            # Structure réelle: analysis.security_issues[] (pas findings)
            analysis = result.get("analysis", {}) if result else {}
            security_issues = analysis.get("security_issues", [])
            
            for idx, issue in enumerate(security_issues):
                vulnerabilities.append({
                    "id": f"NETWORK-{idx+1}",
                    "title": issue.get("type") or "Network Issue",
                    "description": issue.get("description") or "",
                    "severity": issue.get("severity", "MEDIUM").upper(),
                    "file": issue.get("file"),
                    "line": issue.get("line"),
                    "code_snippet": issue.get("detail") or issue.get("url"),
                    "recommendation": issue.get("recommendation"),
                    "tool": "NetworkInspector",
                    "category": "network"
                })
            
            logger.info(f"🌐 NetworkInspector: {len(vulnerabilities)} problèmes pour scan {scan_id}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lecture NetworkInspector: {e}")
        
        return vulnerabilities
    
    def get_all_vulnerabilities(self, scan_id: str) -> Dict[str, Any]:
        """
        Récupère TOUTES les vulnérabilités des 3 microservices pour un scan.
        
        Returns:
            Dict contenant les vulnérabilités par catégorie et le total
        """
        crypto_vulns = self.get_crypto_vulnerabilities(scan_id)
        secret_vulns = self.get_secret_vulnerabilities(scan_id)
        network_vulns = self.get_network_vulnerabilities(scan_id)
        
        all_vulns = crypto_vulns + secret_vulns + network_vulns
        
        return {
            "scan_id": scan_id,
            "total": len(all_vulns),
            "by_tool": {
                "CryptoCheck": len(crypto_vulns),
                "SecretHunter": len(secret_vulns),
                "NetworkInspector": len(network_vulns)
            },
            "vulnerabilities": all_vulns
        }
    
    def save_suggestions(self, scan_id: str, suggestions: List[Dict[str, Any]], model_used: str) -> bool:
        """
        Sauvegarde les suggestions générées dans MongoDB.
        
        Args:
            scan_id: Identifiant du scan
            suggestions: Liste des suggestions générées
            model_used: Modèle LLM utilisé
            
        Returns:
            True si succès, False sinon
        """
        if self.db is None:
            logger.error("❌ MongoDB non connecté, impossible de sauvegarder")
            return False
        
        try:
            doc = {
                "scan_id": scan_id,
                "suggestions": suggestions,
                "suggestions_count": len(suggestions),
                "model_used": model_used,
                "generated_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            # Upsert - met à jour si existe, sinon insère
            self.db.fix_suggestions.update_one(
                {"scan_id": scan_id},
                {"$set": doc},
                upsert=True
            )
            
            logger.info(f"✅ {len(suggestions)} suggestions sauvegardées pour scan {scan_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde suggestions: {e}")
            return False
    
    def get_suggestions(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les suggestions déjà générées pour un scan.
        """
        if self.db is None:
            return None
        
        try:
            result = self.db.fix_suggestions.find_one({"scan_id": scan_id})
            if result:
                result["_id"] = str(result["_id"])  # Convertir ObjectId
            return result
        except Exception as e:
            logger.error(f"❌ Erreur récupération suggestions: {e}")
            return None
    
    def get_scan_info(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les informations de base d'un scan depuis apk_results.
        """
        if self.db is None:
            return None
        
        try:
            result = self.db.apk_results.find_one({"scan_id": scan_id})
            if result:
                return {
                    "scan_id": scan_id,
                    "app_name": result.get("app_name") or result.get("apk_name"),
                    "package_name": result.get("package_name"),
                    "version": result.get("version_name") or result.get("version"),
                    "status": result.get("status")
                }
            return None
        except Exception as e:
            logger.error(f"❌ Erreur récupération scan info: {e}")
            return None


# Instance globale
mongodb_client = MongoDBClient()


def get_mongodb_client() -> MongoDBClient:
    """Retourne l'instance du client MongoDB"""
    return mongodb_client
