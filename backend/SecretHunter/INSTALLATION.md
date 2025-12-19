# Guide d'installation des dépendances SecretHunter

Ce guide vous aidera à installer GitLeaks et yara-python pour SecretHunter.

## 📦 Installation de GitLeaks

### Méthode 1 : Téléchargement manuel (Recommandé)

1. **Téléchargez GitLeaks** :
   - Allez sur : https://github.com/gitleaks/gitleaks/releases
   - Téléchargez `gitleaks-windows-amd64.exe` (dernière version)

2. **Installez GitLeaks** :
   - Créez un dossier pour les binaires (ex: `C:\Users\VotreNom\bin` ou `C:\tools\bin`)
   - Renommez `gitleaks-windows-amd64.exe` en `gitleaks.exe`
   - Placez-le dans ce dossier

3. **Ajoutez au PATH** :
   - Ouvrez les Variables d'environnement Windows
   - Ajoutez le chemin du dossier au PATH utilisateur
   - Redémarrez votre terminal

4. **Vérifiez l'installation** :
   ```powershell
   gitleaks version
   ```

### Méthode 2 : Via Chocolatey (nécessite droits admin)

```powershell
# Ouvrir PowerShell en tant qu'administrateur
choco install gitleaks -y
```

### Méthode 3 : Via Scoop

```powershell
scoop install gitleaks
```

## 🐍 Installation de yara-python

**Note importante** : yara-python est **optionnel**. SecretHunter fonctionne sans YARA, mais le scan YARA sera désactivé.

### Prérequis

yara-python nécessite :
1. **YARA** installé sur le système
2. **Microsoft Visual C++ Build Tools** pour compiler

### Option 1 : Installation complète (nécessite droits admin)

#### Étape 1 : Installer YARA

**Via Chocolatey** (en tant qu'administrateur) :
```powershell
choco install yara -y
```

**Ou téléchargement manuel** :
- Téléchargez YARA depuis : https://github.com/VirusTotal/yara/releases
- Extrayez et ajoutez au PATH

#### Étape 2 : Installer Microsoft Visual C++ Build Tools

1. Téléchargez depuis : https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Installez "C++ build tools"
3. Redémarrez votre terminal

#### Étape 3 : Installer yara-python

```powershell
pip install yara-python
```

### Option 2 : Utiliser SecretHunter sans YARA

Si vous ne souhaitez pas installer YARA, SecretHunter fonctionnera parfaitement avec :
- ✅ Scan regex des fichiers
- ✅ Scan Git avec GitLeaks
- ❌ Scan YARA (désactivé)

Aucune action requise, l'application détectera automatiquement l'absence de YARA.

## ✅ Vérification de l'installation

Exécutez le script de vérification :

```powershell
powershell -ExecutionPolicy Bypass -File install_dependencies.ps1
```

Ou vérifiez manuellement :

```powershell
# Vérifier GitLeaks
gitleaks version

# Vérifier yara-python
python -c "import yara; print('yara-python installé')"
```

## 🚀 Utilisation

Une fois les dépendances installées, vous pouvez utiliser SecretHunter :

```powershell
# Scanner un projet
python cli.py C:\chemin\vers\projet

# Scanner sans Git (si GitLeaks n'est pas installé)
python cli.py C:\chemin\vers\projet --no-git

# Scanner sans YARA (si yara-python n'est pas installé)
python cli.py C:\chemin\vers\projet --no-yara
```

## 🔧 Dépannage

### GitLeaks non trouvé

- Vérifiez que GitLeaks est dans votre PATH
- Redémarrez votre terminal après avoir ajouté au PATH
- Utilisez `--no-git` pour scanner sans GitLeaks

### yara-python ne s'installe pas

- Vérifiez que YARA est installé : `yara --version`
- Vérifiez que Visual C++ Build Tools est installé
- Utilisez `--no-yara` pour scanner sans YARA

### Erreurs de compilation

Si vous obtenez des erreurs lors de l'installation de yara-python :
- Installez Microsoft Visual C++ Build Tools
- Ou utilisez SecretHunter sans YARA (optionnel)

## 📝 Notes

- **GitLeaks** est recommandé pour scanner l'historique Git
- **yara-python** est optionnel mais ajoute des capacités de détection avancées
- SecretHunter fonctionne avec uniquement les scans regex si les autres outils ne sont pas disponibles


