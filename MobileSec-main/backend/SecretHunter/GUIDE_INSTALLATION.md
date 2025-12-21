# Guide d'installation - GitLeaks et YARA

## 🔧 Installation de GitLeaks

### Méthode 1 : Téléchargement manuel (Recommandé)

1. **Ouvrez votre navigateur** et allez sur :
   ```
   https://github.com/gitleaks/gitleaks/releases/latest
   ```

2. **Téléchargez le fichier** :
   - Cherchez `gitleaks-windows-amd64.exe`
   - Cliquez dessus pour télécharger

3. **Créez un dossier pour les outils** :
   - Ouvrez PowerShell ou l'Explorateur de fichiers
   - Créez un dossier : `C:\Users\hp\bin` (ou un autre dossier de votre choix)

4. **Placez GitLeaks dans ce dossier** :
   - Renommez `gitleaks-windows-amd64.exe` en `gitleaks.exe`
   - Déplacez-le dans `C:\Users\hp\bin`

5. **Ajoutez au PATH** :
   - Appuyez sur `Windows + R`
   - Tapez : `sysdm.cpl` et appuyez sur Entrée
   - Allez dans l'onglet "Avancé"
   - Cliquez sur "Variables d'environnement"
   - Dans "Variables utilisateur", trouvez "Path" et cliquez sur "Modifier"
   - Cliquez sur "Nouveau" et ajoutez : `C:\Users\hp\bin`
   - Cliquez sur "OK" partout

6. **Redémarrez votre terminal PowerShell**

7. **Vérifiez l'installation** :
   ```powershell
   gitleaks version
   ```

### Méthode 2 : Via Chocolatey (nécessite droits administrateur)

1. **Ouvrez PowerShell en tant qu'administrateur** :
   - Clic droit sur PowerShell → "Exécuter en tant qu'administrateur"

2. **Installez GitLeaks** :
   ```powershell
   choco install gitleaks -y
   ```

3. **Vérifiez l'installation** :
   ```powershell
   gitleaks version
   ```

---

## 🐍 Installation de YARA et yara-python

### Étape 1 : Installer YARA

#### Option A : Via Chocolatey (nécessite droits administrateur)

1. **Ouvrez PowerShell en tant qu'administrateur**

2. **Installez YARA** :
   ```powershell
   choco install yara -y
   ```

3. **Vérifiez l'installation** :
   ```powershell
   yara --version
   ```

#### Option B : Téléchargement manuel

1. **Téléchargez YARA** :
   - Allez sur : https://github.com/VirusTotal/yara/releases/latest
   - Téléchargez `yara-X.X.X-win64.zip` (la dernière version)

2. **Extrayez l'archive** :
   - Extrayez dans un dossier, par exemple : `C:\Program Files\YARA`

3. **Ajoutez au PATH** :
   - Ajoutez le chemin du dossier YARA à votre PATH (même méthode que pour GitLeaks)
   - Exemple : `C:\Program Files\YARA`

4. **Vérifiez l'installation** :
   ```powershell
   yara --version
   ```

### Étape 2 : Installer Microsoft Visual C++ Build Tools

**IMPORTANT** : yara-python nécessite des outils de compilation.

1. **Téléchargez Visual C++ Build Tools** :
   - Allez sur : https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Cliquez sur "Télécharger Build Tools"

2. **Installez** :
   - Exécutez le fichier téléchargé
   - Cochez "C++ build tools"
   - Cliquez sur "Installer"
   - Attendez la fin de l'installation (peut prendre du temps)

3. **Redémarrez votre ordinateur** (recommandé)

### Étape 3 : Installer yara-python

1. **Ouvrez PowerShell** (normal, pas besoin d'admin)

2. **Installez yara-python** :
   ```powershell
   pip install yara-python
   ```

3. **Vérifiez l'installation** :
   ```powershell
   python -c "import yara; print('yara-python installe avec succes!')"
   ```

---

## ✅ Vérification complète

Exécutez ces commandes pour vérifier que tout est installé :

```powershell
# Vérifier GitLeaks
gitleaks version

# Vérifier YARA
yara --version

# Vérifier yara-python
python -c "import yara; print('OK')"
```

Si toutes les commandes fonctionnent, vous êtes prêt ! 🎉

---

## 🚀 Test de SecretHunter

Une fois tout installé, testez SecretHunter :

```powershell
cd C:\Users\hp\Desktop\SecretHunter
python cli.py .
```

---

## ⚠️ Dépannage

### GitLeaks non trouvé
- Vérifiez que le dossier est dans le PATH
- Redémarrez votre terminal
- Vérifiez l'orthographe : `gitleaks.exe` (pas `gitleaks-windows-amd64.exe`)

### YARA non trouvé
- Vérifiez que YARA est dans le PATH
- Redémarrez votre terminal

### Erreur lors de l'installation de yara-python
- Vérifiez que Visual C++ Build Tools est installé
- Redémarrez votre ordinateur après l'installation
- Réessayez : `pip install yara-python`

### SecretHunter fonctionne sans YARA
- C'est normal ! SecretHunter fonctionne sans yara-python
- Utilisez `--no-yara` si vous ne voulez pas installer YARA


