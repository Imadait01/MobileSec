import hashlib
import random

"""
Exemple de code Python vulnérable pour tester le scanner CryptoCheck.
Ce fichier contient intentionnellement plusieurs vulnérabilités cryptographiques.
"""

def vulnerable_hashing():
    # Vulnérabilité: MD5
    md5_hash = hashlib.md5(b"test").hexdigest()
    
    # Vulnérabilité: SHA-1
    sha1_hash = hashlib.sha1(b"test").hexdigest()

def vulnerable_random():
    # Vulnérabilité: random au lieu de secrets
    value = random.randint(1, 100)

