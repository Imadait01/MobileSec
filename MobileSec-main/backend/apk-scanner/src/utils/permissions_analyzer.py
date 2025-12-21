"""
Module pour analyser les permissions Android et leur niveau de danger
"""
import logging

logger = logging.getLogger(__name__)


class PermissionsAnalyzer:
    """Classe pour analyser les permissions Android"""
    
    # Permissions dangereuses selon la documentation Android
    DANGEROUS_PERMISSIONS = {
        # Groupe CALENDAR
        'android.permission.READ_CALENDAR': 'DANGEROUS',
        'android.permission.WRITE_CALENDAR': 'DANGEROUS',
        
        # Groupe CAMERA
        'android.permission.CAMERA': 'DANGEROUS',
        
        # Groupe CONTACTS
        'android.permission.READ_CONTACTS': 'DANGEROUS',
        'android.permission.WRITE_CONTACTS': 'DANGEROUS',
        'android.permission.GET_ACCOUNTS': 'DANGEROUS',
        
        # Groupe LOCATION
        'android.permission.ACCESS_FINE_LOCATION': 'DANGEROUS',
        'android.permission.ACCESS_COARSE_LOCATION': 'DANGEROUS',
        'android.permission.ACCESS_BACKGROUND_LOCATION': 'DANGEROUS',
        
        # Groupe MICROPHONE
        'android.permission.RECORD_AUDIO': 'DANGEROUS',
        
        # Groupe PHONE
        'android.permission.READ_PHONE_STATE': 'DANGEROUS',
        'android.permission.READ_PHONE_NUMBERS': 'DANGEROUS',
        'android.permission.CALL_PHONE': 'DANGEROUS',
        'android.permission.ANSWER_PHONE_CALLS': 'DANGEROUS',
        'android.permission.READ_CALL_LOG': 'DANGEROUS',
        'android.permission.WRITE_CALL_LOG': 'DANGEROUS',
        'android.permission.ADD_VOICEMAIL': 'DANGEROUS',
        'android.permission.USE_SIP': 'DANGEROUS',
        'android.permission.PROCESS_OUTGOING_CALLS': 'DANGEROUS',
        
        # Groupe SENSORS
        'android.permission.BODY_SENSORS': 'DANGEROUS',
        
        # Groupe SMS
        'android.permission.SEND_SMS': 'DANGEROUS',
        'android.permission.RECEIVE_SMS': 'DANGEROUS',
        'android.permission.READ_SMS': 'DANGEROUS',
        'android.permission.RECEIVE_WAP_PUSH': 'DANGEROUS',
        'android.permission.RECEIVE_MMS': 'DANGEROUS',
        
        # Groupe STORAGE
        'android.permission.READ_EXTERNAL_STORAGE': 'DANGEROUS',
        'android.permission.WRITE_EXTERNAL_STORAGE': 'DANGEROUS',
        'android.permission.ACCESS_MEDIA_LOCATION': 'DANGEROUS',
    }
    
    # Permissions normales communes
    NORMAL_PERMISSIONS = {
        'android.permission.INTERNET': 'NORMAL',
        'android.permission.ACCESS_NETWORK_STATE': 'NORMAL',
        'android.permission.ACCESS_WIFI_STATE': 'NORMAL',
        'android.permission.BLUETOOTH': 'NORMAL',
        'android.permission.BLUETOOTH_ADMIN': 'NORMAL',
        'android.permission.VIBRATE': 'NORMAL',
        'android.permission.WAKE_LOCK': 'NORMAL',
        'android.permission.RECEIVE_BOOT_COMPLETED': 'NORMAL',
        'android.permission.FOREGROUND_SERVICE': 'NORMAL',
        'android.permission.REQUEST_INSTALL_PACKAGES': 'NORMAL',
    }
    
    # Permissions critiques à surveiller
    CRITICAL_PERMISSIONS = {
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.WRITE_SETTINGS',
        'android.permission.PACKAGE_USAGE_STATS',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.REQUEST_DELETE_PACKAGES',
    }
    
    def __init__(self):
        """Initialise l'analyseur de permissions"""
        pass
    
    def analyze_permissions(self, permissions_list):
        """
        Analyse une liste de permissions
        
        Args:
            permissions_list (list): Liste des noms de permissions
            
        Returns:
            dict: Analyse détaillée des permissions
        """
        analysis = {
            'total': len(permissions_list),
            'dangerous': [],
            'normal': [],
            'critical': [],
            'unknown': [],
            'summary': {},
            'risk_score': 0
        }
        
        for perm in permissions_list:
            perm_data = self.get_permission_info(perm)
            
            if perm_data['level'] == 'DANGEROUS':
                analysis['dangerous'].append(perm_data)
            elif perm_data['level'] == 'NORMAL':
                analysis['normal'].append(perm_data)
            elif perm_data['level'] == 'UNKNOWN':
                analysis['unknown'].append(perm_data)
            
            if perm in self.CRITICAL_PERMISSIONS:
                analysis['critical'].append(perm_data)
        
        # Calculer le score de risque
        analysis['risk_score'] = self._calculate_risk_score(analysis)
        
        # Générer un résumé
        analysis['summary'] = {
            'dangerous_count': len(analysis['dangerous']),
            'normal_count': len(analysis['normal']),
            'critical_count': len(analysis['critical']),
            'unknown_count': len(analysis['unknown']),
            'risk_level': self._get_risk_level(analysis['risk_score'])
        }
        
        logger.info(f"Analyzed {len(permissions_list)} permissions. Risk level: {analysis['summary']['risk_level']}")
        
        return analysis
    
    def get_permission_info(self, permission_name):
        """
        Obtient les informations sur une permission
        
        Args:
            permission_name (str): Nom de la permission
            
        Returns:
            dict: Informations sur la permission
        """
        info = {
            'name': permission_name,
            'level': 'UNKNOWN',
            'is_dangerous': False,
            'is_critical': False,
            'description': self._get_permission_description(permission_name),
            'group': self._get_permission_group(permission_name)
        }
        
        if permission_name in self.DANGEROUS_PERMISSIONS:
            info['level'] = 'DANGEROUS'
            info['is_dangerous'] = True
        elif permission_name in self.NORMAL_PERMISSIONS:
            info['level'] = 'NORMAL'
        
        if permission_name in self.CRITICAL_PERMISSIONS:
            info['is_critical'] = True
        
        return info
    
    def _get_permission_description(self, permission_name):
        """
        Retourne une description de la permission
        
        Args:
            permission_name (str): Nom de la permission
            
        Returns:
            str: Description
        """
        descriptions = {
            'android.permission.INTERNET': 'Allows network access',
            'android.permission.CAMERA': 'Allows access to camera',
            'android.permission.READ_CONTACTS': 'Allows reading contacts',
            'android.permission.WRITE_CONTACTS': 'Allows writing contacts',
            'android.permission.ACCESS_FINE_LOCATION': 'Allows precise location access',
            'android.permission.ACCESS_COARSE_LOCATION': 'Allows approximate location access',
            'android.permission.RECORD_AUDIO': 'Allows audio recording',
            'android.permission.READ_PHONE_STATE': 'Allows reading phone state',
            'android.permission.SEND_SMS': 'Allows sending SMS',
            'android.permission.READ_SMS': 'Allows reading SMS',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Allows writing to external storage',
            'android.permission.READ_EXTERNAL_STORAGE': 'Allows reading from external storage',
            'android.permission.SYSTEM_ALERT_WINDOW': 'Allows drawing over other apps',
            'android.permission.REQUEST_INSTALL_PACKAGES': 'Allows requesting package installation',
        }
        
        return descriptions.get(permission_name, 'No description available')
    
    def _get_permission_group(self, permission_name):
        """
        Retourne le groupe de la permission
        
        Args:
            permission_name (str): Nom de la permission
            
        Returns:
            str: Groupe
        """
        if 'CALENDAR' in permission_name:
            return 'CALENDAR'
        elif 'CAMERA' in permission_name:
            return 'CAMERA'
        elif 'CONTACTS' in permission_name or 'ACCOUNTS' in permission_name:
            return 'CONTACTS'
        elif 'LOCATION' in permission_name:
            return 'LOCATION'
        elif 'MICROPHONE' in permission_name or 'RECORD_AUDIO' in permission_name:
            return 'MICROPHONE'
        elif 'PHONE' in permission_name or 'CALL' in permission_name:
            return 'PHONE'
        elif 'SENSORS' in permission_name or 'BODY_SENSORS' in permission_name:
            return 'SENSORS'
        elif 'SMS' in permission_name or 'MMS' in permission_name:
            return 'SMS'
        elif 'STORAGE' in permission_name:
            return 'STORAGE'
        elif 'INTERNET' in permission_name or 'NETWORK' in permission_name:
            return 'NETWORK'
        else:
            return 'OTHER'
    
    def _calculate_risk_score(self, analysis):
        """
        Calcule un score de risque basé sur les permissions
        
        Args:
            analysis (dict): Analyse des permissions
            
        Returns:
            int: Score de risque (0-100)
        """
        score = 0
        
        # Chaque permission dangereuse ajoute des points
        score += len(analysis['dangerous']) * 10
        
        # Les permissions critiques ajoutent plus de points
        score += len(analysis['critical']) * 20
        
        # Les permissions inconnues ajoutent des points
        score += len(analysis['unknown']) * 5
        
        # Limiter le score à 100
        return min(score, 100)
    
    def _get_risk_level(self, risk_score):
        """
        Détermine le niveau de risque basé sur le score
        
        Args:
            risk_score (int): Score de risque
            
        Returns:
            str: Niveau de risque
        """
        if risk_score >= 70:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def get_security_recommendations(self, analysis):
        """
        Génère des recommandations de sécurité
        
        Args:
            analysis (dict): Analyse des permissions
            
        Returns:
            list: Liste de recommandations
        """
        recommendations = []
        
        if len(analysis['dangerous']) > 10:
            recommendations.append({
                'severity': 'WARNING',
                'message': f"Application requests {len(analysis['dangerous'])} dangerous permissions. Review if all are necessary."
            })
        
        if analysis['critical']:
            recommendations.append({
                'severity': 'CRITICAL',
                'message': f"Application uses {len(analysis['critical'])} critical permissions that could pose security risks."
            })
        
        # Vérifier des combinaisons dangereuses
        perm_names = [p['name'] for p in analysis['dangerous']]
        
        if 'android.permission.INTERNET' in perm_names and 'android.permission.READ_CONTACTS' in perm_names:
            recommendations.append({
                'severity': 'WARNING',
                'message': "Application can access contacts and internet. Ensure data is transmitted securely."
            })
        
        if 'android.permission.SEND_SMS' in perm_names and 'android.permission.INTERNET' in perm_names:
            recommendations.append({
                'severity': 'WARNING',
                'message': "Application can send SMS and access internet. Monitor for potential premium SMS fraud."
            })
        
        return recommendations
