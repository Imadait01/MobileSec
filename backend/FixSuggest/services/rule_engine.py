"""
FixSuggest - Rule Engine
=========================
Charge et gère les règles MASVS depuis les fichiers YAML.
Effectue le matching entre vulnérabilités et règles.
"""

import os
import yaml
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

from models import MASVSRule, Vulnerability
from config import settings

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Moteur de règles MASVS.
    Charge les règles depuis les fichiers YAML et effectue le matching.
    """
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialise le moteur de règles.
        
        Args:
            rules_path: Chemin vers le dossier des règles YAML
        """
        self.rules_path = Path(rules_path or settings.rules_path)
        self.rules: Dict[str, MASVSRule] = {}
        self._trigger_index: Dict[str, List[str]] = {}  # trigger -> [rule_ids]
        
        self._load_rules()
    
    def _load_rules(self) -> None:
        """
        Charge toutes les règles MASVS depuis les fichiers YAML.
        """
        if not self.rules_path.exists():
            logger.warning(f"Rules path does not exist: {self.rules_path}")
            self._create_default_rules()
            return
        
        yaml_files = list(self.rules_path.glob("*.yaml")) + list(self.rules_path.glob("*.yml"))
        
        if not yaml_files:
            logger.warning(f"No YAML files found in {self.rules_path}")
            self._create_default_rules()
            return
        
        for yaml_file in yaml_files:
            try:
                self._load_yaml_file(yaml_file)
            except Exception as e:
                logger.error(f"Error loading {yaml_file}: {e}")
        
        logger.info(f"Loaded {len(self.rules)} MASVS rules from {len(yaml_files)} files")
        self._build_trigger_index()
    
    def _load_yaml_file(self, file_path: Path) -> None:
        """
        Charge un fichier YAML contenant des règles.
        
        Args:
            file_path: Chemin vers le fichier YAML
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
        
        if not content:
            return
        
        # Gérer le format liste ou dict
        rules_data = content if isinstance(content, list) else content.get('rules', [content])
        
        for rule_data in rules_data:
            try:
                # Mapping des champs YAML vers les champs du modèle Pydantic
                mapped_data = {
                    'rule_id': rule_data.get('id', rule_data.get('rule_id', '')),
                    'title': rule_data.get('title', ''),
                    'description': rule_data.get('description', ''),
                    'triggers': rule_data.get('triggers', []),
                    'recommendation': rule_data.get('remediation', rule_data.get('recommendation', '')),
                    'patches': rule_data.get('patches', {}),
                    'references': rule_data.get('references', []),
                    'severity': rule_data.get('severity', 'medium')
                }
                
                rule = MASVSRule(**mapped_data)
                self.rules[rule.rule_id] = rule
                logger.debug(f"Loaded rule: {rule.rule_id}")
            except Exception as e:
                logger.warning(f"Invalid rule in {file_path}: {e}")
    
    def _build_trigger_index(self) -> None:
        """
        Construit un index inversé des triggers pour un matching rapide.
        """
        self._trigger_index.clear()
        
        for rule_id, rule in self.rules.items():
            for trigger in rule.triggers:
                trigger_lower = trigger.lower()
                if trigger_lower not in self._trigger_index:
                    self._trigger_index[trigger_lower] = []
                self._trigger_index[trigger_lower].append(rule_id)
        
        logger.debug(f"Built trigger index with {len(self._trigger_index)} triggers")
    
    def _create_default_rules(self) -> None:
        """
        Crée des règles par défaut si aucun fichier n'est trouvé.
        """
        default_rules = [
            MASVSRule(
                rule_id="MASVS-CRYPTO-01",
                title="Strong Cryptography",
                description="L'application utilise des algorithmes cryptographiques modernes et sécurisés.",
                triggers=["AES-ECB", "AES/ECB", "ECB_MODE", "ecb", "DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1"],
                recommendation="Utiliser AES/GCM/NoPadding ou AES/CBC/PKCS7Padding avec un IV aléatoire. Éviter ECB, DES, 3DES, RC4.",
                patches={
                    "java": """// Remplacement sécurisé
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

// Générer une clé AES-256
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256, new SecureRandom());
SecretKey secretKey = keyGen.generateKey();

// Créer un IV aléatoire
byte[] iv = new byte[12]; // 96 bits pour GCM
new SecureRandom().nextBytes(iv);
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

// Utiliser AES/GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
byte[] ciphertext = cipher.doFinal(plaintext);""",
                    "kotlin": """// Remplacement sécurisé en Kotlin
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

val keyGen = KeyGenerator.getInstance("AES").apply { init(256) }
val secretKey = keyGen.generateKey()

val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
val gcmSpec = GCMParameterSpec(128, iv)

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
val ciphertext = cipher.doFinal(plaintext)""",
                    "smali": """# Note: Le code Smali doit être modifié dans la source Java/Kotlin originale
# Remplacer les appels à Cipher.getInstance("AES") ou "AES/ECB"
# par Cipher.getInstance("AES/GCM/NoPadding")"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/05-MASVS-CRYPTO/",
                    "https://cwe.mitre.org/data/definitions/327.html"
                ],
                severity="high"
            ),
            MASVSRule(
                rule_id="MASVS-CRYPTO-02",
                title="Secure Random Number Generation",
                description="L'application utilise des générateurs de nombres aléatoires cryptographiquement sécurisés.",
                triggers=["Random()", "java.util.Random", "Math.random", "WEAK_RANDOM", "weak_random"],
                recommendation="Remplacer java.util.Random par java.security.SecureRandom pour toutes les opérations cryptographiques.",
                patches={
                    "java": """// Remplacement sécurisé
import java.security.SecureRandom;

// Au lieu de: Random random = new Random();
SecureRandom secureRandom = new SecureRandom();

// Générer des bytes aléatoires
byte[] randomBytes = new byte[32];
secureRandom.nextBytes(randomBytes);

// Générer un nombre aléatoire
int randomInt = secureRandom.nextInt();""",
                    "kotlin": """// Remplacement sécurisé en Kotlin
import java.security.SecureRandom

val secureRandom = SecureRandom()
val randomBytes = ByteArray(32).also { secureRandom.nextBytes(it) }
val randomInt = secureRandom.nextInt()"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/05-MASVS-CRYPTO/",
                    "https://cwe.mitre.org/data/definitions/330.html"
                ],
                severity="medium"
            ),
            MASVSRule(
                rule_id="MASVS-CRYPTO-03",
                title="Secure Hash Functions",
                description="L'application utilise des fonctions de hachage sécurisées.",
                triggers=["MD5", "SHA1", "SHA-1", "md5", "sha1", "MessageDigest.getInstance"],
                recommendation="Remplacer MD5 et SHA-1 par SHA-256 ou SHA-512. Pour les mots de passe, utiliser bcrypt, scrypt ou Argon2.",
                patches={
                    "java": """// Remplacement sécurisé
import java.security.MessageDigest;

// Au lieu de: MessageDigest.getInstance("MD5") ou "SHA-1"
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(data);

// Pour les mots de passe, utiliser BCrypt:
// import org.mindrot.jbcrypt.BCrypt;
// String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/05-MASVS-CRYPTO/",
                    "https://cwe.mitre.org/data/definitions/328.html"
                ],
                severity="high"
            ),
            MASVSRule(
                rule_id="MASVS-STORAGE-01",
                title="Secure Data Storage",
                description="L'application stocke les données sensibles de manière sécurisée.",
                triggers=["SharedPreferences", "getSharedPreferences", "HARDCODED_KEY", "hardcoded", "password=", "secret="],
                recommendation="Utiliser EncryptedSharedPreferences ou Android Keystore pour stocker les données sensibles. Ne jamais hardcoder les clés.",
                patches={
                    "java": """// Utiliser EncryptedSharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secret_shared_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/07-MASVS-STORAGE/",
                    "https://developer.android.com/topic/security/data"
                ],
                severity="high"
            ),
            MASVSRule(
                rule_id="MASVS-NETWORK-01",
                title="Secure Network Communication",
                description="L'application utilise des communications réseau sécurisées.",
                triggers=["http://", "cleartext", "CLEARTEXT", "allowCleartextTraffic", "insecure", "SSL", "TLS"],
                recommendation="Utiliser HTTPS exclusivement. Configurer network_security_config.xml pour interdire le trafic en clair.",
                patches={
                    "xml": """<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/06-MASVS-NETWORK/",
                    "https://developer.android.com/training/articles/security-config"
                ],
                severity="medium"
            ),
            MASVSRule(
                rule_id="MASVS-PLATFORM-01",
                title="Secure Platform Interaction",
                description="L'application interagit de manière sécurisée avec la plateforme.",
                triggers=["exported=true", "android:exported", "intent-filter", "EXPORTED", "debuggable"],
                recommendation="Définir android:exported=false sauf si nécessaire. Valider les données des Intents.",
                patches={
                    "xml": """<!-- AndroidManifest.xml -->
<!-- Au lieu de: android:exported="true" -->
<activity
    android:name=".MyActivity"
    android:exported="false">
</activity>

<!-- Si exported est nécessaire, ajouter des permissions -->
<activity
    android:name=".ExportedActivity"
    android:exported="true"
    android:permission="com.example.MY_PERMISSION">
</activity>"""
                },
                references=[
                    "https://mas.owasp.org/MASVS/08-MASVS-PLATFORM/"
                ],
                severity="medium"
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.rule_id] = rule
        
        logger.info(f"Created {len(default_rules)} default MASVS rules")
        self._build_trigger_index()
    
    def find_matching_rules(self, vulnerability: Vulnerability) -> List[MASVSRule]:
        """
        Trouve les règles MASVS correspondant à une vulnérabilité.
        
        Args:
            vulnerability: La vulnérabilité à analyser
            
        Returns:
            Liste des règles MASVS correspondantes
        """
        matching_rules = set()
        
        # Textes à rechercher
        search_texts = [
            vulnerability.id or "",
            vulnerability.title or "",
            vulnerability.description or "",
            vulnerability.cwe or "",
            vulnerability.code_snippet or ""
        ]
        
        combined_text = " ".join(search_texts).lower()
        
        # Recherche dans l'index des triggers
        for trigger, rule_ids in self._trigger_index.items():
            if trigger in combined_text:
                matching_rules.update(rule_ids)
        
        # Retourner les règles correspondantes
        return [self.rules[rule_id] for rule_id in matching_rules if rule_id in self.rules]
    
    def get_rule(self, rule_id: str) -> Optional[MASVSRule]:
        """
        Récupère une règle par son ID.
        
        Args:
            rule_id: Identifiant de la règle
            
        Returns:
            La règle ou None si non trouvée
        """
        return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[MASVSRule]:
        """
        Retourne toutes les règles chargées.
        
        Returns:
            Liste de toutes les règles
        """
        return list(self.rules.values())
    
    def get_rules_count(self) -> int:
        """
        Retourne le nombre de règles chargées.
        
        Returns:
            Nombre de règles
        """
        return len(self.rules)


# Instance globale du moteur de règles
rule_engine = RuleEngine()


def get_rule_engine() -> RuleEngine:
    """
    Retourne l'instance du moteur de règles.
    """
    return rule_engine
