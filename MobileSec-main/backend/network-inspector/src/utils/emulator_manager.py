"""
Module pour gérer l'émulateur Android via Docker

Ce module permet de :
- Lancer un container Android (émulateur)
- Installer des APK
- Configurer le proxy réseau
- Contrôler le cycle de vie du container
"""
import logging
import subprocess
import time
import os
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class EmulatorManager:
    """Gestionnaire d'émulateur Android avec Docker"""
    
    def __init__(self, container_name='android-emulator'):
        """
        Initialise le gestionnaire d'émulateur
        
        Args:
            container_name (str): Nom du container Docker
        """
        self.container_name = container_name
        self.container_id = None
        self.is_running = False
        self.adb_port = 5555
        self.emulator_port = 5554
    
    def check_docker(self) -> bool:
        """
        Vérifie que Docker est disponible
        
        Returns:
            bool: True si Docker est disponible
        """
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Docker available: {result.stdout.strip()}")
                return True
            return False
        except Exception as e:
            logger.error(f"Docker not available: {e}")
            return False
    
    def start_emulator(self, image='budtmo/docker-android:emulator_11.0', proxy_host='host.docker.internal', proxy_port=8080) -> bool:
        """
        Lance l'émulateur Android dans un container Docker
        
        Args:
            image (str): Image Docker à utiliser
            proxy_host (str): Hôte du proxy
            proxy_port (int): Port du proxy
            
        Returns:
            bool: True si démarré avec succès
        """
        try:
            logger.info(f"Starting Android emulator container: {self.container_name}")
            
            # Arrêter le container existant s'il y en a un
            self.stop_emulator()
            
            # Commande Docker pour lancer l'émulateur
            cmd = [
                'docker', 'run', '-d',
                '--name', self.container_name,
                '--privileged',
                '-p', f'{self.adb_port}:{self.adb_port}',
                '-p', f'{self.emulator_port}:{self.emulator_port}',
                '-e', f'EMULATOR_DEVICE=Samsung Galaxy S10',
                '-e', 'WEB_VNC=true',
                image
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.container_id = result.stdout.strip()
                logger.info(f"Emulator container started: {self.container_id}")
                
                # Attendre que l'émulateur soit prêt
                if self.wait_for_emulator():
                    self.is_running = True
                    
                    # Configurer le proxy
                    if self.configure_proxy(proxy_host, proxy_port):
                        logger.info("Proxy configured successfully")
                    
                    return True
                else:
                    logger.error("Emulator failed to start properly")
                    return False
            else:
                logger.error(f"Failed to start emulator: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout starting emulator")
            return False
        except Exception as e:
            logger.error(f"Error starting emulator: {e}")
            return False
    
    def wait_for_emulator(self, timeout=180) -> bool:
        """
        Attend que l'émulateur soit complètement démarré
        
        Args:
            timeout (int): Timeout en secondes
            
        Returns:
            bool: True si l'émulateur est prêt
        """
        logger.info("Waiting for emulator to be ready...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Vérifier si le container est en cours d'exécution
                result = subprocess.run(
                    ['docker', 'ps', '--filter', f'name={self.container_name}', '--format', '{{.Status}}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if 'Up' in result.stdout:
                    logger.info("Emulator container is up")
                    # Attendre un peu plus pour que l'émulateur soit complètement initialisé
                    time.sleep(30)
                    return True
                
            except Exception as e:
                logger.debug(f"Error checking emulator status: {e}")
            
            time.sleep(5)
        
        logger.error("Timeout waiting for emulator")
        return False
    
    def configure_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Configure le proxy réseau dans l'émulateur
        
        Args:
            proxy_host (str): Hôte du proxy
            proxy_port (int): Port du proxy
            
        Returns:
            bool: True si configuré avec succès
        """
        try:
            logger.info(f"Configuring proxy: {proxy_host}:{proxy_port}")
            
            # Exécuter adb shell dans le container pour configurer le proxy
            # Note: Cette commande peut varier selon l'image Docker utilisée
            cmd = [
                'docker', 'exec', self.container_name,
                'adb', 'shell',
                'settings', 'put', 'global', 'http_proxy',
                f'{proxy_host}:{proxy_port}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("Proxy configured successfully")
                return True
            else:
                logger.warning(f"Failed to configure proxy: {result.stderr}")
                return False
                
        except Exception as e:
            logger.warning(f"Error configuring proxy: {e}")
            return False
    
    def install_apk(self, apk_path: str) -> bool:
        """
        Installe un APK dans l'émulateur
        
        Args:
            apk_path (str): Chemin vers le fichier APK
            
        Returns:
            bool: True si installé avec succès
        """
        try:
            if not os.path.exists(apk_path):
                logger.error(f"APK file not found: {apk_path}")
                return False
            
            logger.info(f"Installing APK: {apk_path}")
            
            # Copier l'APK dans le container
            copy_cmd = [
                'docker', 'cp',
                apk_path,
                f'{self.container_name}:/tmp/app.apk'
            ]
            
            result = subprocess.run(
                copy_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to copy APK to container: {result.stderr}")
                return False
            
            # Installer l'APK
            install_cmd = [
                'docker', 'exec', self.container_name,
                'adb', 'install', '-r', '/tmp/app.apk'
            ]
            
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and 'Success' in result.stdout:
                logger.info("APK installed successfully")
                return True
            else:
                logger.error(f"Failed to install APK: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout installing APK")
            return False
        except Exception as e:
            logger.error(f"Error installing APK: {e}")
            return False
    
    def launch_app(self, package_name: str, activity: Optional[str] = None) -> bool:
        """
        Lance une application dans l'émulateur
        
        Args:
            package_name (str): Nom du package
            activity (str): Activité à lancer (optionnel)
            
        Returns:
            bool: True si lancé avec succès
        """
        try:
            logger.info(f"Launching app: {package_name}")
            
            if activity:
                launch_cmd = f'{package_name}/{activity}'
            else:
                # Essayer de lancer l'activité principale
                launch_cmd = package_name
            
            cmd = [
                'docker', 'exec', self.container_name,
                'adb', 'shell', 'monkey',
                '-p', package_name,
                '-c', 'android.intent.category.LAUNCHER', '1'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("App launched successfully")
                return True
            else:
                logger.warning(f"Failed to launch app: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error launching app: {e}")
            return False
    
    def interact_with_app(self, duration: int = 30) -> bool:
        """
        Simule l'interaction avec l'application
        
        Args:
            duration (int): Durée en secondes
            
        Returns:
            bool: True si succès
        """
        try:
            logger.info(f"Interacting with app for {duration} seconds...")
            
            # Utiliser monkey pour générer des événements aléatoires
            cmd = [
                'docker', 'exec', self.container_name,
                'adb', 'shell', 'monkey',
                '--throttle', '500',
                duration * 2  # Nombre d'événements
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 10
            )
            
            logger.info("App interaction completed")
            return True
            
        except Exception as e:
            logger.warning(f"Error during app interaction: {e}")
            return False
    
    def stop_emulator(self) -> bool:
        """
        Arrête et supprime le container de l'émulateur
        
        Returns:
            bool: True si arrêté avec succès
        """
        try:
            logger.info(f"Stopping emulator container: {self.container_name}")
            
            # Arrêter le container
            subprocess.run(
                ['docker', 'stop', self.container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Supprimer le container
            subprocess.run(
                ['docker', 'rm', self.container_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            self.is_running = False
            self.container_id = None
            logger.info("Emulator stopped and removed")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping emulator: {e}")
            return False
    
    def get_emulator_info(self) -> Dict:
        """
        Récupère les informations sur l'émulateur
        
        Returns:
            dict: Informations sur l'émulateur
        """
        info = {
            'container_name': self.container_name,
            'container_id': self.container_id,
            'is_running': self.is_running,
            'adb_port': self.adb_port,
            'emulator_port': self.emulator_port
        }
        
        if self.is_running:
            try:
                # Obtenir le statut du container
                result = subprocess.run(
                    ['docker', 'inspect', self.container_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    import json
                    container_info = json.loads(result.stdout)[0]
                    info['status'] = container_info['State']['Status']
                    info['started_at'] = container_info['State']['StartedAt']
                    
            except Exception as e:
                logger.debug(f"Error getting emulator info: {e}")
        
        return info
