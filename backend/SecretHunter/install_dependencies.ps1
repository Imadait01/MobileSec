# Script d'installation des dependances pour SecretHunter
# Ce script installe GitLeaks automatiquement

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation des dependances SecretHunter" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verifier si GitLeaks est deja installe
$gitleaksInstalled = $false
try {
    $version = gitleaks version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "GitLeaks est deja installe: $version" -ForegroundColor Green
        $gitleaksInstalled = $true
    }
} catch {
    # GitLeaks n'est pas installe
}

if (-not $gitleaksInstalled) {
    Write-Host "Installation de GitLeaks..." -ForegroundColor Yellow
    
    # URL de la derniere release de GitLeaks pour Windows
    $gitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-windows-amd64.exe"
    $gitleaksPath = "$env:USERPROFILE\.local\bin\gitleaks.exe"
    $binDir = "$env:USERPROFILE\.local\bin"
    
    # Creer le dossier si necessaire
    if (-not (Test-Path $binDir)) {
        New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    }
    
    try {
        Write-Host "Telechargement de GitLeaks..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $gitleaksUrl -OutFile $gitleaksPath -UseBasicParsing
        
        Write-Host "GitLeaks telecharge avec succes" -ForegroundColor Green
        
        # Ajouter au PATH de l'utilisateur si pas deja present
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$binDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
            Write-Host "Ajoute au PATH utilisateur" -ForegroundColor Green
            Write-Host "  Note: Vous devrez peut-etre redemarrer votre terminal pour que le PATH soit mis a jour" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "GitLeaks installe avec succes dans: $gitleaksPath" -ForegroundColor Green
        
    } catch {
        Write-Host "Erreur lors du telechargement de GitLeaks: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Installation manuelle:" -ForegroundColor Yellow
        Write-Host "1. Telechargez GitLeaks depuis: https://github.com/gitleaks/gitleaks/releases" -ForegroundColor Yellow
        Write-Host "2. Extrayez gitleaks.exe dans un dossier de votre PATH" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation de yara-python" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verifier si yara-python est installe
try {
    python -c "import yara" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "yara-python est deja installe" -ForegroundColor Green
    }
} catch {
    Write-Host "yara-python n'est pas installe" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT: yara-python necessite YARA et des outils de compilation." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options d'installation:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Option 1 (Recommandé - necessite droits admin):" -ForegroundColor Green
    Write-Host "  1. Installez YARA via Chocolatey (en tant qu administrateur):" -ForegroundColor White
    Write-Host "     choco install yara -y" -ForegroundColor Gray
    Write-Host "  2. Installez Microsoft Visual C++ Build Tools:" -ForegroundColor White
    Write-Host "     https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Gray
    Write-Host "  3. Installez yara-python:" -ForegroundColor White
    Write-Host "     pip install yara-python" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Option 2 (Alternative - sans YARA):" -ForegroundColor Green
    Write-Host "  SecretHunter fonctionne sans YARA. Le scan YARA sera simplement desactive." -ForegroundColor White
    Write-Host "  Vous pouvez utiliser uniquement les scans regex et GitLeaks." -ForegroundColor White
    Write-Host ""
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Resume" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verifier les installations
$allGood = $true

# Verifier GitLeaks
try {
    $gitleaksVersion = gitleaks version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "GitLeaks: Installe" -ForegroundColor Green
    } else {
        Write-Host "GitLeaks: Non installe" -ForegroundColor Red
        $allGood = $false
    }
} catch {
    Write-Host "GitLeaks: Non installe" -ForegroundColor Red
    $allGood = $false
}

# Verifier yara-python
try {
    python -c "import yara" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "yara-python: Installe" -ForegroundColor Green
    } else {
        Write-Host "yara-python: Non installe (optionnel)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "yara-python: Non installe (optionnel)" -ForegroundColor Yellow
}

Write-Host ""
if ($allGood) {
    Write-Host "Toutes les dependances principales sont installees!" -ForegroundColor Green
} else {
    Write-Host "Certaines dependances manquent. SecretHunter fonctionnera mais certaines fonctionnalites seront desactivees." -ForegroundColor Yellow
}
