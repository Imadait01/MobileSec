# Script PowerShell pour forcer le rechargement du projet dans IntelliJ IDEA
# Ce script aide a resoudre les problemes de supertypes non resolus

Write-Host "=== CryptoCheck - Rechargement du projet ===" -ForegroundColor Cyan
Write-Host ""

# Nettoyer les fichiers de build
Write-Host "1. Nettoyage des fichiers de build..." -ForegroundColor Yellow
if (Test-Path "target") {
    Remove-Item -Recurse -Force "target" -ErrorAction SilentlyContinue
    Write-Host "   OK - Dossier target supprime" -ForegroundColor Green
}

# Nettoyer les caches IntelliJ
Write-Host "2. Nettoyage des caches IntelliJ..." -ForegroundColor Yellow
if (Test-Path ".idea\libraries") {
    Remove-Item -Recurse -Force ".idea\libraries" -ErrorAction SilentlyContinue
    Write-Host "   OK - Bibliotheques IntelliJ supprimees" -ForegroundColor Green
}

# Verifier Maven
Write-Host "3. Verification de Maven..." -ForegroundColor Yellow
$mvnVersion = mvn -version 2>&1 | Select-String "Apache Maven"
if ($mvnVersion) {
    Write-Host "   OK - Maven trouve" -ForegroundColor Green
} else {
    Write-Host "   ERREUR - Maven non trouve!" -ForegroundColor Red
    exit 1
}

# Telecharger les dependances
Write-Host "4. Telechargement des dependances..." -ForegroundColor Yellow
mvn dependency:resolve -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK - Dependances resolues" -ForegroundColor Green
} else {
    Write-Host "   ERREUR - lors du telechargement des dependances" -ForegroundColor Red
    exit 1
}

# Compiler le projet
Write-Host "5. Compilation du projet..." -ForegroundColor Yellow
mvn compile -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK - Compilation reussie" -ForegroundColor Green
} else {
    Write-Host "   ERREUR - lors de la compilation" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Actions a effectuer dans IntelliJ IDEA ===" -ForegroundColor Cyan
Write-Host "1. Cliquez avec le bouton droit sur pom.xml" -ForegroundColor White
Write-Host "2. Selectionnez 'Maven' -> 'Reload project'" -ForegroundColor White
Write-Host "3. Attendez que l'indexation se termine" -ForegroundColor White
Write-Host ""
Write-Host "Si le probleme persiste, allez dans:" -ForegroundColor Yellow
Write-Host "File -> Invalidate Caches / Restart -> Invalidate and Restart" -ForegroundColor White
Write-Host ""
Write-Host "=== Termine ===" -ForegroundColor Green

