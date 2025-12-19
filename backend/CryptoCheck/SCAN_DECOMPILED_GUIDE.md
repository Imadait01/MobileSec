# 🎯 GUIDE - Scanner le dossier uptodown-com.kiloo.subwaysurf_decompiled

## ✅ Votre chemin configuré :
```
C:\Users\hp\Downloads\uptodown-com.kiloo.subwaysurf_decompiled
```

---

## 🚀 MÉTHODE 1 : GET Simple (LA PLUS RAPIDE) ⭐

**Nouveau endpoint créé spécialement pour vous !**

### Depuis votre navigateur :
```
http://localhost:8080/api/scan/default
```

### Avec curl :
```bash
curl http://localhost:8080/api/scan/default
```

### Avec PowerShell :
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/scan/default"
```

**Aucun paramètre à envoyer !** Le chemin est automatiquement utilisé.

---

## 🔧 MÉTHODE 2 : POST avec le chemin

### Avec curl :
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"directoryPath\":\"C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled\"}"
```

### Avec PowerShell :
```powershell
$body = @{
    directoryPath = "C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/scan" -Method POST -Body $body -ContentType "application/json"
```

### Avec Postman / IntelliJ HTTP Client :
```http
POST http://localhost:8080/api/scan
Content-Type: application/json

{
  "directoryPath": "C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled"
}
```

---

## ⚙️ Configuration dans application.properties

Le chemin est maintenant configurable dans :
```properties
# src/main/resources/application.properties
crypto.scanner.default-path=C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled
```

**Pour changer le chemin :** Modifiez simplement cette ligne et redémarrez l'application.

---

## 📊 Résultat attendu

```json
{
  "scanDate": "2025-11-23T18:30:00",
  "totalFiles": 156,
  "vulnerabilities": [
    {
      "type": "WEAK_HASH_ALGORITHM",
      "severity": "HIGH",
      "filePath": "C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled/com/example/Class.java",
      "lineNumber": 45,
      "codeSnippet": "MessageDigest.getInstance(\"MD5\")",
      "description": "Utilisation de l'algorithme de hachage faible : MD5",
      "recommendation": "Utilisez SHA-256 ou SHA-3"
    },
    // ... autres vulnérabilités
  ]
}
```

---

## 🧪 Test complet

### 1. Démarrer l'application :
```bash
mvn spring-boot:run
```

### 2. Scanner le dossier (méthode GET simple) :
```bash
curl http://localhost:8080/api/scan/default
```

### 3. Récupérer le dernier rapport :
```bash
curl http://localhost:8080/api/report
```

---

## 📁 Endpoints disponibles

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| **GET** | `/api/scan/default` | ⭐ Scanner le chemin par défaut (le plus simple) |
| **POST** | `/api/scan` | Scanner un chemin spécifique |
| **POST** | `/api/scan/upload` | Recevoir un fichier uploadé |
| **POST** | `/api/scan/upload-multiple` | Scanner plusieurs fichiers |
| **POST** | `/api/scan/remote` | Scanner via URL |
| **GET** | `/api/report` | Récupérer le dernier rapport |

---

## ⚠️ Important

### Si le dossier n'existe pas :
Vous verrez cette erreur :
```json
{
  "error": "Erreur de validation",
  "message": "Le dossier spécifié n'existe pas : C:/Users/hp/Downloads/uptodown-com.kiloo.subwaysurf_decompiled"
}
```

### Solution :
Vérifiez que le chemin existe :
```powershell
Test-Path "C:\Users\hp\Downloads\uptodown-com.kiloo.subwaysurf_decompiled"
```

---

## 🎯 RÉCAPITULATIF

### Pour scanner votre dossier décompilé :

#### Option la plus simple (recommandée) :
```bash
# Juste un GET, rien d'autre !
curl http://localhost:8080/api/scan/default
```

#### Ou depuis votre navigateur :
```
http://localhost:8080/api/scan/default
```

**C'est tout ! Le chemin est déjà configuré dans application.properties** 🎉

---

## 🔧 Personnalisation

Pour changer le chemin par défaut, modifiez dans `application.properties` :
```properties
crypto.scanner.default-path=C:/VotreNouveauChemin/MonDossier
```

Puis redémarrez l'application.

---

**Le scanner est maintenant configuré pour votre dossier décompilé !** 🚀

