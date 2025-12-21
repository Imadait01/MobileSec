"""
Module pour parser et analyser le fichier AndroidManifest.xml
"""
import logging
import subprocess
import os
from pathlib import Path
from lxml import etree

logger = logging.getLogger(__name__)


class ManifestParser:
    """Classe pour parser le manifest Android"""
    
    def __init__(self, apk_path):
        """
        Initialise le parser avec le chemin de l'APK
        
        Args:
            apk_path (str): Chemin vers le fichier APK
        """
        self.apk_path = apk_path
        self.manifest_path = None
        self.manifest_tree = None
        self.decompiled_dir = None
    
    def decompile_apk(self, output_dir='output'):
        """
        Décompile l'APK avec apktool
        
        Args:
            output_dir (str): Répertoire de sortie
            
        Returns:
            str: Chemin du répertoire décompilé
        """
        apk_name = Path(self.apk_path).stem
        self.decompiled_dir = os.path.join(output_dir, apk_name)
        
        try:
            # Supprimer le répertoire s'il existe déjà
            if os.path.exists(self.decompiled_dir):
                import shutil
                shutil.rmtree(self.decompiled_dir)
            
            # Exécuter apktool
            cmd = ['apktool', 'd', self.apk_path, '-o', self.decompiled_dir, '-f']
            logger.info(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                logger.error(f"Apktool error: {result.stderr}")
                raise Exception(f"Apktool failed: {result.stderr}")
            
            logger.info(f"APK decompiled successfully to {self.decompiled_dir}")
            
            # Localiser le manifest
            self.manifest_path = os.path.join(self.decompiled_dir, 'AndroidManifest.xml')
            
            if not os.path.exists(self.manifest_path):
                raise FileNotFoundError(f"Manifest not found at {self.manifest_path}")
            
            return self.decompiled_dir
            
        except subprocess.TimeoutExpired:
            logger.error("Apktool timeout")
            raise Exception("Apktool execution timed out")
        except Exception as e:
            logger.error(f"Decompilation error: {e}")
            raise
    
    def parse_manifest(self):
        """
        Parse le fichier AndroidManifest.xml
        
        Returns:
            dict: Données du manifest parsées
        """
        if not self.manifest_path or not os.path.exists(self.manifest_path):
            raise FileNotFoundError("Manifest file not found. Run decompile_apk first.")
        
        try:
            # Parser le XML
            parser = etree.XMLParser(remove_blank_text=True)
            self.manifest_tree = etree.parse(self.manifest_path, parser)
            root = self.manifest_tree.getroot()
            
            # Namespace Android
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            manifest_data = {
                'package': root.get('package'),
                'version_code': root.get('{http://schemas.android.com/apk/res/android}versionCode'),
                'version_name': root.get('{http://schemas.android.com/apk/res/android}versionName'),
                'min_sdk': None,
                'target_sdk': None,
                'debuggable': False,
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
                'exported_components': []
            }
            
            # Récupérer uses-sdk
            uses_sdk = root.find('uses-sdk', ns)
            if uses_sdk is not None:
                manifest_data['min_sdk'] = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
                manifest_data['target_sdk'] = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
            
            # Vérifier si debuggable
            application = root.find('application', ns)
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
                manifest_data['debuggable'] = debuggable == 'true'
                
                # Vérifier cleartext traffic
                cleartext = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
                manifest_data['cleartext_allowed'] = cleartext != 'false'  # True par défaut si non spécifié
                
                # Network security config
                network_config = application.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
                manifest_data['network_security_config'] = network_config
                
                # Parser les composants
                manifest_data['activities'] = self._parse_components(application, 'activity', ns)
                manifest_data['services'] = self._parse_components(application, 'service', ns)
                manifest_data['receivers'] = self._parse_components(application, 'receiver', ns)
                manifest_data['providers'] = self._parse_components(application, 'provider', ns)
            
            # Récupérer les permissions
            manifest_data['permissions'] = self._parse_permissions(root, ns)
            
            # Lister tous les composants exportés
            manifest_data['exported_components'] = self._get_exported_components(manifest_data)
            
            logger.info(f"Manifest parsed successfully for package: {manifest_data['package']}")
            
            return manifest_data
            
        except Exception as e:
            logger.error(f"Error parsing manifest: {e}")
            raise
    
    def _parse_permissions(self, root, ns):
        """
        Parse les permissions du manifest
        
        Args:
            root: Racine de l'arbre XML
            ns: Namespace
            
        Returns:
            list: Liste des permissions
        """
        permissions = []
        
        for perm in root.findall('uses-permission', ns):
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
            if perm_name:
                permissions.append(perm_name)
        
        return permissions
    
    def _parse_components(self, application, component_type, ns):
        """
        Parse un type de composant (activity, service, receiver, provider)
        
        Args:
            application: Élément application
            component_type (str): Type de composant
            ns: Namespace
            
        Returns:
            list: Liste des composants
        """
        components = []
        
        for comp in application.findall(component_type, ns):
            name = comp.get('{http://schemas.android.com/apk/res/android}name')
            exported = comp.get('{http://schemas.android.com/apk/res/android}exported')
            
            # Par défaut, un composant avec intent-filter est exporté
            has_intent_filter = len(comp.findall('intent-filter', ns)) > 0
            
            is_exported = False
            if exported == 'true':
                is_exported = True
            elif exported is None and has_intent_filter:
                is_exported = True
            
            intent_filters = []
            for intent_filter in comp.findall('intent-filter', ns):
                filter_data = {
                    'actions': [a.get('{http://schemas.android.com/apk/res/android}name') 
                               for a in intent_filter.findall('action', ns)],
                    'categories': [c.get('{http://schemas.android.com/apk/res/android}name') 
                                  for c in intent_filter.findall('category', ns)]
                }
                intent_filters.append(filter_data)
            
            components.append({
                'name': name,
                'type': component_type,
                'exported': is_exported,
                'intent_filters': intent_filters
            })
        
        return components
    
    def _get_exported_components(self, manifest_data):
        """
        Extrait tous les composants exportés
        
        Args:
            manifest_data (dict): Données du manifest
            
        Returns:
            list: Liste des composants exportés
        """
        exported = []
        
        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            for comp in manifest_data.get(comp_type, []):
                if comp.get('exported'):
                    exported.append(comp)
        
        return exported
    
    def get_security_issues(self, manifest_data):
        """
        Identifie les problèmes de sécurité potentiels
        
        Args:
            manifest_data (dict): Données du manifest
            
        Returns:
            list: Liste des problèmes de sécurité
        """
        issues = []
        
        # Vérifier si debuggable
        if manifest_data.get('debuggable'):
            issues.append({
                'severity': 'HIGH',
                'type': 'debuggable',
                'message': 'Application is debuggable in production'
            })
        
        # Vérifier cleartext traffic
        if manifest_data.get('cleartext_allowed'):
            issues.append({
                'severity': 'MEDIUM',
                'type': 'cleartext_traffic',
                'message': 'Application allows cleartext traffic (HTTP)'
            })
        
        # Vérifier les composants exportés
        exported_count = len(manifest_data.get('exported_components', []))
        if exported_count > 0:
            issues.append({
                'severity': 'INFO',
                'type': 'exported_components',
                'message': f'{exported_count} components are exported',
                'count': exported_count
            })
        
        return issues
    
    def cleanup(self):
        """Nettoie les fichiers temporaires"""
        if self.decompiled_dir and os.path.exists(self.decompiled_dir):
            try:
                import shutil
                shutil.rmtree(self.decompiled_dir)
                logger.info(f"Cleaned up {self.decompiled_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup: {e}")
