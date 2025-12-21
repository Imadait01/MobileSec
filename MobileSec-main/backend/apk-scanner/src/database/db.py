"""
Module de gestion de la base de données SQLite pour stocker les métadonnées des scans APK
"""
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class Database:
    """Classe pour gérer la base de données SQLite"""
    
    def __init__(self, db_path='database/apk_scans.db'):
        """
        Initialise la connexion à la base de données
        
        Args:
            db_path (str): Chemin vers le fichier de base de données
        """
        self.db_path = db_path
        # Créer le répertoire si nécessaire
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def get_connection(self):
        """Crée et retourne une connexion à la base de données"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Pour accéder aux colonnes par nom
        return conn
    
    def init_database(self):
        """Initialise les tables de la base de données"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Table principale des scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_name TEXT NOT NULL,
                package_name TEXT,
                version_code TEXT,
                version_name TEXT,
                min_sdk INTEGER,
                target_sdk INTEGER,
                debuggable BOOLEAN,
                cleartext_allowed BOOLEAN,
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_status TEXT,
                file_hash TEXT UNIQUE
            )
        ''')
        
        # Table des permissions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                permission_name TEXT NOT NULL,
                permission_level TEXT,
                is_dangerous BOOLEAN,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')
        
        # Table des composants exportés
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exported_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                component_type TEXT NOT NULL,
                component_name TEXT NOT NULL,
                is_exported BOOLEAN,
                intent_filters TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')
        
        # Table des endpoints réseau
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                method TEXT,
                protocol TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')
        
        # Table des résultats complets (JSON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER UNIQUE,
                full_report TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def save_scan(self, scan_data):
        """
        Sauvegarde un scan complet dans la base de données
        
        Args:
            scan_data (dict): Données du scan
            
        Returns:
            int: ID du scan créé
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Insérer le scan principal
            cursor.execute('''
                INSERT INTO scans (
                    apk_name, package_name, version_code, version_name,
                    min_sdk, target_sdk, debuggable, cleartext_allowed,
                    scan_status, file_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_data.get('apk_name'),
                scan_data.get('package_name'),
                scan_data.get('version_code'),
                scan_data.get('version_name'),
                scan_data.get('min_sdk'),
                scan_data.get('target_sdk'),
                scan_data.get('debuggable', False),
                scan_data.get('cleartext_allowed', False),
                scan_data.get('scan_status', 'completed'),
                scan_data.get('file_hash')
            ))
            
            scan_id = cursor.lastrowid
            
            # Insérer les permissions
            if 'permissions' in scan_data:
                for perm in scan_data['permissions']:
                    cursor.execute('''
                        INSERT INTO permissions (
                            scan_id, permission_name, permission_level, is_dangerous
                        ) VALUES (?, ?, ?, ?)
                    ''', (
                        scan_id,
                        perm.get('name'),
                        perm.get('level'),
                        perm.get('is_dangerous', False)
                    ))
            
            # Insérer les composants exportés
            if 'exported_components' in scan_data:
                for comp in scan_data['exported_components']:
                    cursor.execute('''
                        INSERT INTO exported_components (
                            scan_id, component_type, component_name, 
                            is_exported, intent_filters
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        comp.get('type'),
                        comp.get('name'),
                        comp.get('exported', False),
                        json.dumps(comp.get('intent_filters', []))
                    ))
            
            # Insérer les endpoints réseau
            if 'endpoints' in scan_data:
                for endpoint in scan_data['endpoints']:
                    cursor.execute('''
                        INSERT INTO network_endpoints (
                            scan_id, url, method, protocol
                        ) VALUES (?, ?, ?, ?)
                    ''', (
                        scan_id,
                        endpoint.get('url'),
                        endpoint.get('method'),
                        endpoint.get('protocol')
                    ))
            
            # Insérer le rapport complet
            cursor.execute('''
                INSERT INTO scan_results (scan_id, full_report)
                VALUES (?, ?)
            ''', (scan_id, json.dumps(scan_data)))
            
            conn.commit()
            logger.info(f"Scan saved successfully with ID: {scan_id}")
            return scan_id
            
        except sqlite3.IntegrityError as e:
            logger.error(f"Database integrity error: {e}")
            conn.rollback()
            raise
        except Exception as e:
            logger.error(f"Error saving scan: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_scan_by_id(self, scan_id):
        """
        Récupère un scan par son ID
        
        Args:
            scan_id (int): ID du scan
            
        Returns:
            dict: Données du scan ou None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            conn.close()
            return None
        
        # Récupérer le rapport complet
        cursor.execute('SELECT full_report FROM scan_results WHERE scan_id = ?', (scan_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return json.loads(result['full_report'])
        return None
    
    def get_scan_by_hash(self, file_hash):
        """
        Récupère un scan par le hash du fichier
        
        Args:
            file_hash (str): Hash MD5 du fichier APK
            
        Returns:
            dict: Données du scan ou None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM scans WHERE file_hash = ?', (file_hash,))
        scan = cursor.fetchone()
        
        conn.close()
        
        if scan:
            return self.get_scan_by_id(scan['id'])
        return None
    
    def get_all_scans(self, limit=100):
        """
        Récupère tous les scans (limité)
        
        Args:
            limit (int): Nombre maximum de résultats
            
        Returns:
            list: Liste des scans
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, apk_name, package_name, scan_timestamp, scan_status
            FROM scans
            ORDER BY scan_timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return scans
    
    def delete_scan(self, scan_id):
        """
        Supprime un scan et toutes ses données associées
        
        Args:
            scan_id (int): ID du scan à supprimer
            
        Returns:
            bool: True si supprimé, False sinon
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            logger.info(f"Scan {scan_id} deleted: {deleted}")
            return deleted
        except Exception as e:
            logger.error(f"Error deleting scan: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def get_statistics(self):
        """
        Récupère des statistiques sur les scans
        
        Returns:
            dict: Statistiques
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Nombre total de scans
        cursor.execute('SELECT COUNT(*) as total FROM scans')
        stats['total_scans'] = cursor.fetchone()['total']
        
        # Nombre d'APKs debuggable
        cursor.execute('SELECT COUNT(*) as count FROM scans WHERE debuggable = 1')
        stats['debuggable_apps'] = cursor.fetchone()['count']
        
        # Nombre d'APKs avec cleartext autorisé
        cursor.execute('SELECT COUNT(*) as count FROM scans WHERE cleartext_allowed = 1')
        stats['cleartext_allowed_apps'] = cursor.fetchone()['count']
        
        # Permissions les plus communes
        cursor.execute('''
            SELECT permission_name, COUNT(*) as count
            FROM permissions
            GROUP BY permission_name
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['top_permissions'] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return stats
