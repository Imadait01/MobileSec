# CryptoCheck - Scanner SAST pour Vulnérabilités Cryptographiques

CryptoCheck est un scanner SAST (Static Application Security Testing) spécialisé dans la détection des vulnérabilités cryptographiques dans le code source. Il analyse automatiquement les fichiers de code et identifie les mauvaises pratiques cryptographiques selon les standards CWE.

## 🎯 Fonctionnalités

- **Scanner multi-langages** : Supporte Java, Kotlin, Python, C#, JavaScript, TypeScript
- **Détection de vulnérabilités cryptographiques** :
  - AES en mode ECB (non sécurisé)
  - Absence de padding dans AES
  - Générateurs aléatoires faibles (Random vs SecureRandom)
  - Hachages obsolètes (MD5, SHA-1)
- **API REST** : Endpoints pour lancer des scans et récupérer des rapports
- **Rapports JSON** : Format structuré avec recommandations de correction
- **Architecture extensible** : Facile d'ajouter de nouvelles règles CWE

## 🏗️ Architecture

Le projet suit une architecture microservice avec Spring Boot :

```
src/main/kotlin/com/cryptocheck/
├── controller/          # Contrôleurs REST (API endpoints)
├── service/            # Services métier
├── scanner/            # Scanner SAST et règles de détection
└── model/              # Modèles de données (Vulnerability, ScanReport)
```

## 🚀 Démarrage rapide

### Prérequis

- Java 17 ou supérieur
- Maven 3.6+
- Kotlin 1.9.20+ (géré automatiquement par Maven)

### Installation

1. Cloner le projet :
```bash
git clone <repository-url>
cd CryptoCheck
```

2. Compiler le projet :
```bash
mvn clean install
```

3. Lancer l'application :
```bash
mvn spring-boot:run
```

L'API sera accessible sur `http://localhost:8080`

## 📡 API REST

### POST /api/scan

Lance un scan sur un dossier donné.

**Requête :**
```json
{
  "directoryPath": "/chemin/vers/dossier"
}
```

**Réponse :**
```json
{
  "scannedPath": "/chemin/vers/dossier",
  "scanDate": "2024-01-15T10:30:00",
  "totalVulnerabilities": 3,
  "scanDurationMs": 150,
  "vulnerabilities": [
    {
      "file": "src/example/code.py",
      "line": 15,
      "vulnerability": "AES/ECB usage",
      "cwe": "CWE-327",
      "recommendation": "Remplacer AES/ECB par AES/GCM/NoPadding ou AES/CBC/PKCS5Padding avec un IV aléatoire",
      "codeSnippet": "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"
    }
  ]
}
```

### GET /api/report

Récupère le dernier rapport de scan généré.

**Réponse :** Même format que POST /api/scan

## 🔍 Types de vulnérabilités détectées

| Vulnérabilité | CWE | Description |
|--------------|-----|-------------|
| AES/ECB usage | CWE-327 | Utilisation d'AES en mode ECB (non sécurisé) |
| AES without proper padding | CWE-327 | Absence de padding dans l'utilisation d'AES |
| Weak random generator | CWE-330 | Utilisation de `Random` au lieu de `SecureRandom` |
| MD5 hash usage | CWE-327 | Utilisation de MD5 (algorithme obsolète) |
| SHA-1 hash usage | CWE-327 | Utilisation de SHA-1 (algorithme obsolète) |

## 📝 Exemples d'utilisation

### Exemple avec cURL

```bash
# Lancer un scan
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"directoryPath": "/chemin/vers/votre/projet"}'

# Récupérer le rapport
curl http://localhost:8080/api/report
```

### Exemple avec Python

```python
import requests

# Lancer un scan
response = requests.post(
    'http://localhost:8080/api/scan',
    json={'directoryPath': '/chemin/vers/projet'}
)
report = response.json()

# Afficher les vulnérabilités
for vuln in report['vulnerabilities']:
    print(f"{vuln['file']}:{vuln['line']} - {vuln['vulnerability']}")
    print(f"  Recommandation: {vuln['recommendation']}\n")
```

## 🧪 Tests

Exécuter les tests unitaires :

```bash
mvn test
```

Les tests couvrent :
- Détection de chaque type de vulnérabilité
- Scanner multi-langages
- Gestion des erreurs
- API REST

## 🔧 Ajouter une nouvelle règle CWE

Pour ajouter une nouvelle règle de détection :

1. Ajouter un nouvel enum dans `VulnerabilityType.java` :
```java
NEW_VULNERABILITY(
    "Description",
    "CWE-XXX",
    "Recommandation"
)
```

2. Ajouter un pattern de détection dans `CodeScanner.java` :
```java
private static final Pattern NEW_PATTERN = Pattern.compile(
    "(?i)(pattern-to-detect)",
    Pattern.MULTILINE
);
```

3. Ajouter la logique de détection dans la méthode `scanFile()` :
```java
if (NEW_PATTERN.matcher(line).find()) {
    vulnerabilities.add(createVulnerability(
        filePath, lineNumber, VulnerabilityType.NEW_VULNERABILITY, line
    ));
}
```

4. Ajouter un test unitaire dans `CodeScannerTest.java`

## 📦 Structure du projet

```
CryptoCheck/
├── src/
│   ├── main/
│   │   ├── java/com/cryptocheck/
│   │   │   ├── controller/      # API REST
│   │   │   ├── service/         # Services métier
│   │   │   ├── scanner/         # Scanner SAST
│   │   │   └── model/           # Modèles de données
│   │   └── resources/
│   │       └── application.properties
│   └── test/                    # Tests unitaires
├── pom.xml                      # Configuration Maven
└── README.md
```

## 🛠️ Technologies utilisées

- **Kotlin** : Langage de programmation principal
- **Spring Boot 3.2.0** : Framework pour l'API REST
- **Maven** : Gestion des dépendances
- **JUnit 5** : Tests unitaires
- **Mockito Kotlin** : Framework de mocking pour les tests
- **Jackson** : Sérialisation JSON

## 📄 Licence

Ce projet est fourni sous licence MIT.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Ouvrir une issue pour signaler un bug
- Proposer de nouvelles règles CWE
- Améliorer la documentation
- Ajouter le support pour de nouveaux langages

## 📚 Références

- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Spring Boot Documentation](https://spring.io/projects/spring-boot)

