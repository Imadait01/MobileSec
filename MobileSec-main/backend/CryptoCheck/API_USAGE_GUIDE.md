# 📋 Guide d'utilisation - CryptoCheck API

## 🎯 Où mettre le chemin du fichier à scanner ?

Votre microservice CryptoCheck supporte maintenant **4 méthodes** pour recevoir des fichiers depuis un autre microservice :

---

## 🔧 Méthode 1 : Chemin local (Original)

**Endpoint :** `POST /api/scan`

**Utilisation :** Quand le fichier est déjà sur le serveur

**Requête :**
```json
POST http://localhost:8080/api/scan
Content-Type: application/json

{
  "directoryPath": "C:/Users/hp/Documents/MonProjet"
}
```

**Exemple avec curl :**
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"directoryPath":"C:/Users/hp/Documents/MonProjet"}'
```

---

## ✅ Méthode 2 : Upload de fichier (RECOMMANDÉ pour microservices)

**Endpoint :** `POST /api/scan/upload`

**Utilisation :** L'autre microservice envoie le fichier directement

**Requête :**
```bash
POST http://localhost:8080/api/scan/upload
Content-Type: multipart/form-data

file: [fichier à uploader]
```

**Exemple avec curl :**
```bash
curl -X POST http://localhost:8080/api/scan/upload \
  -F "file=@/path/to/VulnerableCode.java"
```

**Exemple depuis un autre microservice (Java/Spring) :**
```java
RestTemplate restTemplate = new RestTemplate();
HttpHeaders headers = new HttpHeaders();
headers.setContentType(MediaType.MULTIPART_FORM_DATA);

MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
body.add("file", new FileSystemResource(new File("/path/to/file.java")));

HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
ResponseEntity<ScanReport> response = restTemplate.postForEntity(
    "http://localhost:8080/api/scan/upload",
    requestEntity,
    ScanReport.class
);
```

**Exemple depuis un autre microservice (Python) :**
```python
import requests

url = "http://localhost:8080/api/scan/upload"
files = {'file': open('VulnerableCode.java', 'rb')}
response = requests.post(url, files=files)
print(response.json())
```

---

## 📦 Méthode 3 : Upload multiple de fichiers

**Endpoint :** `POST /api/scan/upload-multiple`

**Utilisation :** Pour scanner plusieurs fichiers en une seule requête

**Requête :**
```bash
POST http://localhost:8080/api/scan/upload-multiple
Content-Type: multipart/form-data

files: [fichier1]
files: [fichier2]
files: [fichier3]
```

**Exemple avec curl :**
```bash
curl -X POST http://localhost:8080/api/scan/upload-multiple \
  -F "files=@file1.java" \
  -F "files=@file2.py" \
  -F "files=@file3.kt"
```

---

## 🌐 Méthode 4 : URL distante

**Endpoint :** `POST /api/scan/remote`

**Utilisation :** Quand le fichier est accessible via une URL temporaire

**Requête :**
```json
POST http://localhost:8080/api/scan/remote
Content-Type: application/json

{
  "fileUrl": "http://autre-microservice:8081/files/download/abc123"
}
```

**Exemple avec curl :**
```bash
curl -X POST http://localhost:8080/api/scan/remote \
  -H "Content-Type: application/json" \
  -d '{"fileUrl":"http://autre-microservice:8081/files/abc123"}'
```

---

## 📊 Récupérer le dernier rapport

**Endpoint :** `GET /api/report`

**Requête :**
```bash
GET http://localhost:8080/api/report
```

**Exemple avec curl :**
```bash
curl http://localhost:8080/api/report
```

---

## 📝 Format de réponse

Tous les endpoints de scan retournent le même format de rapport :

```json
{
  "scanDate": "2025-11-23T17:30:00",
  "totalFiles": 5,
  "vulnerabilities": [
    {
      "type": "WEAK_HASH_ALGORITHM",
      "severity": "HIGH",
      "filePath": "C:/temp/VulnerableCode.java",
      "lineNumber": 15,
      "codeSnippet": "MessageDigest.getInstance(\"MD5\")",
      "description": "Utilisation de l'algorithme de hachage faible : MD5",
      "recommendation": "Utilisez SHA-256 ou SHA-3 pour le hachage cryptographique"
    }
  ]
}
```

---

## 🚀 Exemple complet d'intégration

### Depuis un microservice Spring Boot :

```kotlin
@Service
class FileAnalysisService {
    
    @Value("\${cryptocheck.url}")
    private lateinit var cryptoCheckUrl: String
    
    fun scanFile(file: MultipartFile): ScanReport {
        val restTemplate = RestTemplate()
        
        val headers = HttpHeaders()
        headers.contentType = MediaType.MULTIPART_FORM_DATA
        
        val body = LinkedMultiValueMap<String, Any>()
        body.add("file", file.resource)
        
        val requestEntity = HttpEntity(body, headers)
        
        return restTemplate.postForObject(
            "$cryptoCheckUrl/api/scan/upload",
            requestEntity,
            ScanReport::class.java
        ) ?: throw RuntimeException("Échec du scan")
    }
}
```

### Configuration dans `application.properties` :

```properties
# URL du microservice CryptoCheck
cryptocheck.url=http://localhost:8080

# Configuration upload (si nécessaire)
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
```

---

## 🎯 Quelle méthode choisir ?

| Méthode | Cas d'usage |
|---------|-------------|
| **Méthode 1 (chemin local)** | Fichier déjà sur le serveur CryptoCheck |
| **Méthode 2 (upload)** | ✅ **RECOMMANDÉ** - Communication directe entre microservices |
| **Méthode 3 (upload multiple)** | Scanner plusieurs fichiers en une fois |
| **Méthode 4 (URL)** | Fichier temporaire accessible via HTTP |

---

## 🔍 Test avec Postman ou curl

### Test rapide avec un fichier local :

```bash
# Créer un fichier de test
echo 'MessageDigest.getInstance("MD5")' > test.java

# L'envoyer au scanner
curl -X POST http://localhost:8080/api/scan/upload \
  -F "file=@test.java"
```

---

## 📞 Support

Pour toute question sur l'intégration avec votre microservice, consultez :
- `ScanController.kt` - Code source des endpoints
- `ScanService.kt` - Logique métier du scanner
- Logs : Les détails de chaque scan sont loggés

---

**Version :** 1.0.0  
**Dernière mise à jour :** 2025-11-23

