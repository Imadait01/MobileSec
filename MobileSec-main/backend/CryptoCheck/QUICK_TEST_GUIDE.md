# 🧪 Tests rapides - CryptoCheck API

## 📋 Prérequis
- CryptoCheck en cours d'exécution : `mvn spring-boot:run`
- Port par défaut : 8080

---

## ✅ Test 1 : Scanner un fichier uploadé (RECOMMANDÉ)

### Créer un fichier de test :
```bash
# Windows PowerShell
@"
import java.security.MessageDigest;

public class VulnerableCode {
    public void weakHash() {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
"@ | Out-File -FilePath test-file.java -Encoding UTF8
```

### L'envoyer au scanner :
```bash
# Avec curl (Windows)
curl -X POST http://localhost:8080/api/scan/upload -F "file=@test-file.java"

# Avec PowerShell
$uri = "http://localhost:8080/api/scan/upload"
$filePath = "test-file.java"
Invoke-RestMethod -Uri $uri -Method Post -InFile $filePath -ContentType "multipart/form-data"
```

### Réponse attendue :
```json
{
  "scanDate": "2025-11-23T18:00:00",
  "totalFiles": 1,
  "vulnerabilities": [
    {
      "type": "WEAK_HASH_ALGORITHM",
      "severity": "HIGH",
      "filePath": "...",
      "lineNumber": 5,
      "codeSnippet": "MessageDigest.getInstance(\"MD5\")",
      "description": "Utilisation de l'algorithme de hachage faible : MD5",
      "recommendation": "Utilisez SHA-256 ou SHA-3"
    }
  ]
}
```

---

## 📦 Test 2 : Scanner plusieurs fichiers

### Créer plusieurs fichiers :
```bash
# Fichier 1 - MD5
@"
MessageDigest.getInstance("MD5");
"@ | Out-File -FilePath file1.java -Encoding UTF8

# Fichier 2 - DES
@"
Cipher.getInstance("DES");
"@ | Out-File -FilePath file2.java -Encoding UTF8

# Fichier 3 - Hardcoded password
@"
String password = "admin123";
"@ | Out-File -FilePath file3.py -Encoding UTF8
```

### Les scanner ensemble :
```bash
curl -X POST http://localhost:8080/api/scan/upload-multiple \
  -F "files=@file1.java" \
  -F "files=@file2.java" \
  -F "files=@file3.py"
```

---

## 🌐 Test 3 : Scanner via URL

Si vous avez un fichier accessible en ligne :

```bash
curl -X POST http://localhost:8080/api/scan/remote \
  -H "Content-Type: application/json" \
  -d "{\"fileUrl\":\"https://raw.githubusercontent.com/example/repo/main/VulnerableCode.java\"}"
```

---

## 📂 Test 4 : Scanner un dossier local

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"directoryPath\":\"C:/Users/hp/Desktop/Microservices/CryptoCheck/examples\"}"
```

---

## 📊 Test 5 : Récupérer le dernier rapport

```bash
curl http://localhost:8080/api/report
```

---

## 🔧 Test depuis un autre microservice

### Exemple en Spring Boot (Kotlin) :

```kotlin
@RestController
@RequestMapping("/api/files")
class FileController {
    
    @PostMapping("/analyze")
    fun analyzeFile(@RequestParam("file") file: MultipartFile): ResponseEntity<*> {
        val restTemplate = RestTemplate()
        
        val headers = HttpHeaders()
        headers.contentType = MediaType.MULTIPART_FORM_DATA
        
        val body = LinkedMultiValueMap<String, Any>()
        body.add("file", file.resource)
        
        val requestEntity = HttpEntity(body, headers)
        
        return try {
            val response = restTemplate.postForEntity(
                "http://localhost:8080/api/scan/upload",
                requestEntity,
                String::class.java
            )
            ResponseEntity.ok(response.body)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Erreur lors de l'analyse : ${e.message}")
        }
    }
}
```

### Exemple en Python (Flask) :

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_file():
    file = request.files['file']
    
    # Envoyer au CryptoCheck
    response = requests.post(
        'http://localhost:8080/api/scan/upload',
        files={'file': file}
    )
    
    return response.json()

if __name__ == '__main__':
    app.run(port=8081)
```

---

## 🎯 Script de test complet (PowerShell)

```powershell
# test-cryptocheck.ps1
Write-Host "=== Test CryptoCheck API ===" -ForegroundColor Cyan

# 1. Créer un fichier vulnérable
$testCode = @"
import java.security.MessageDigest;
public class Test {
    public void test() {
        MessageDigest.getInstance("MD5");
    }
}
"@
$testCode | Out-File -FilePath "test.java" -Encoding UTF8
Write-Host "1. Fichier de test créé" -ForegroundColor Green

# 2. Uploader et scanner
Write-Host "2. Envoi au scanner..." -ForegroundColor Yellow
$uri = "http://localhost:8080/api/scan/upload"
$form = @{
    file = Get-Item -Path "test.java"
}
$response = Invoke-RestMethod -Uri $uri -Method Post -Form $form

# 3. Afficher les résultats
Write-Host "3. Résultats:" -ForegroundColor Green
Write-Host "   Fichiers scannés: $($response.totalFiles)" -ForegroundColor White
Write-Host "   Vulnérabilités: $($response.vulnerabilities.Count)" -ForegroundColor White

if ($response.vulnerabilities.Count -gt 0) {
    Write-Host "`n   Détails:" -ForegroundColor Yellow
    $response.vulnerabilities | ForEach-Object {
        Write-Host "   - Type: $($_.type)" -ForegroundColor Red
        Write-Host "     Ligne: $($_.lineNumber)" -ForegroundColor White
        Write-Host "     Code: $($_.codeSnippet)" -ForegroundColor Gray
    }
}

# 4. Nettoyer
Remove-Item "test.java"
Write-Host "`n=== Test terminé ===" -ForegroundColor Cyan
```

**Exécuter le script :**
```powershell
.\test-cryptocheck.ps1
```

---

## 🐛 Dépannage

### Le serveur ne répond pas :
```bash
# Vérifier si le serveur est lancé
curl http://localhost:8080/actuator/health
```

### Erreur "Connection refused" :
- Vérifier que CryptoCheck est démarré : `mvn spring-boot:run`
- Vérifier le port dans `application.properties`

### Erreur "File too large" :
Modifier `application.properties` :
```properties
spring.servlet.multipart.max-file-size=50MB
spring.servlet.multipart.max-request-size=50MB
```

---

## 📚 Exemples de fichiers vulnérables

### MD5 Hash (Java) :
```java
MessageDigest.getInstance("MD5");
```

### DES Cipher (Java) :
```java
Cipher.getInstance("DES");
```

### Hardcoded Password (Python) :
```python
password = "admin123"
```

### Weak Random (Kotlin) :
```kotlin
val random = java.util.Random()
```

---

**Pour plus d'informations, consultez :** `API_USAGE_GUIDE.md`

