# SecretHunter 🔍🔐

**SecretHunter** is a comprehensive DevSecOps security scanner designed to detect exposed secrets, API keys, credentials, and sensitive data in source code, mobile applications (APK/IPA), and Git repositories.

```
╔═══════════════════════════════════════════════╗
║   SecretHunter - Mobile & DevSecOps Scanner   ║
╚═══════════════════════════════════════════════╝
```

## Features

- ✅ **Multi-Layer Scanning**: Combines regex patterns, GitLeaks, and YARA rules for comprehensive detection
- 📱 **Mobile App Analysis**: Automatic APK decompilation and scanning (smali, resources, assets, binary strings)
- 🔍 **Source Code Scanning**: Supports 30+ programming languages and file formats
- 🌐 **Git History Analysis**: Scans entire Git commit history using GitLeaks
- 🎯 **Pattern-Based Detection**: YARA rules for advanced secret detection
- 📊 **Risk Scoring**: Automated severity assessment (HIGH/MEDIUM/LOW)
- 📄 **JSON Reports**: Detailed findings with file paths, line numbers, and remediation guidance
- 🚀 **CI/CD Ready**: Easy integration into DevSecOps pipelines

## Supported Secret Types

### Cloud & Infrastructure
- AWS Access Keys, Secret Keys, Session Tokens
- Google Cloud API Keys, Firebase Keys
- Azure Storage Keys, Service Principal Credentials
- Heroku API Keys

### Mobile SDKs
- Firebase API Keys & Database URLs
- Google Maps API Keys
- Facebook App IDs & Access Tokens
- Twitter API Keys & Bearer Tokens
- OneSignal Push Notification Keys
- Crashlytics API Keys
- Mixpanel, Amplitude, Segment Tokens

### Payment Gateways
- Stripe API Keys (test & live)
- PayPal Braintree Tokens
- Square Access Tokens & OAuth Secrets

### Authentication & Tokens
- JWT Tokens
- OAuth Tokens
- GitHub Personal Access Tokens
- Slack Tokens
- SendGrid API Keys
- Twilio API Keys

### Credentials
- Hardcoded Passwords
- Database Connection Strings (MySQL, PostgreSQL, MongoDB, Redis)
- Private Keys (RSA, EC, DSA, OpenSSH)
- SSL/TLS Certificates
- Android Keystore Passwords

### Mobile-Specific
- Android Keystore Credentials
- iOS Push Certificates
- Smali Bytecode Hardcoded Strings
- AndroidManifest.xml Secrets
- iOS Info.plist API Keys

## Installation

### Prerequisites

**Python Requirements:**
```bash
pip install -r requirements.txt
```

**Required Tools:**
- **apktool** (for APK decompilation)
- **jadx** (optional, for Java source decompilation)
- **gitleaks** (for Git history scanning)
- **yara-python** (for YARA rule scanning)

### Quick Install (Linux/WSL/macOS)

```bash
# Clone the repository
git clone https://github.com/yourusername/SecretHunter.git
cd SecretHunter

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# Install system tools (Linux/WSL)
sudo apt update
sudo apt install -y apktool jadx yara libyara-dev

# Install GitLeaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.0_linux_x64.tar.gz
```

### Windows Installation

```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install tools
choco install gitleaks -y

# Create Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

# For APK scanning on Windows, use WSL with apktool/jadx
```

## Usage

### Basic Scanning

**Scan a Source Code Directory:**
```bash
python cli.py /path/to/project
```

**Scan an APK File:**
```bash
python cli.py /path/to/app.apk
```

**Custom Output Path:**
```bash
python cli.py /path/to/project --output custom_report.json
```

### Advanced Options

```bash
# Skip Git history scanning
python cli.py /path/to/project --no-git

# Skip YARA scanning
python cli.py /path/to/project --no-yara

# Skip file regex scanning
python cli.py /path/to/project --no-file-scan

# Use custom patterns
python cli.py /path/to/project --rules-path custom_patterns.json

# Use custom YARA rules
python cli.py /path/to/project --yara-rules-path custom_rules.yar

# Specify custom GitLeaks path
python cli.py /path/to/project --gitleaks-path /custom/path/to/gitleaks
```

### APK Scanning Workflow

When you provide an APK file, SecretHunter automatically:

1. **Extracts** raw APK contents (resources, assets, lib, manifest)
2. **Decompiles** with apktool (decoded XML, smali bytecode)
3. **Decompiles** with jadx (Java source code from DEX)
4. **Extracts** all strings from DEX files using androguard
5. **Scans** all decompiled content with regex, YARA rules
6. **Generates** comprehensive security report

**Example:**
```bash
python cli.py myapp.apk

# Output:
# ============================================================
# SecretHunter - Mobile & DevSecOps Security Scanner
# ============================================================
# [APK DETECTED] Starting APK decompilation...
# 
# [1/4] Extracting raw APK contents...
# [2/4] Decompiling with apktool...
# [3/4] Decompiling with jadx...
# [4/4] Extracting strings from DEX...
#
# [1/3] Scanning files with regex patterns...
# [2/3] Git scanning skipped (not applicable for decompiled APK)
# [3/3] Scanning files with YARA rules...
#
# Report saved to: output/secrethunter_report.json
```

## Report Format

SecretHunter generates a JSON report with the following structure:

```json
{
  "summary": {
    "total_findings": 42,
    "high_severity": 15,
    "medium_severity": 20,
    "low_severity": 7,
    "risk_score": {
      "total_score": 185,
      "max_score": 420,
      "risk_level": "CRITICAL"
    }
  },
  "findings": [
    {
      "type": "regex",
      "rule_name": "Firebase API Key",
      "severity": "HIGH",
      "file_path": "smali/com/example/app/Config.smali",
      "line_number": 42,
      "match": "AIzaSyD1234567890abcdefghijklmnopqrs",
      "description": "Firebase/FCM API key detected",
      "source": "file_scanner"
    }
  ],
  "findings_by_severity": {
    "HIGH": [...],
    "MEDIUM": [...],
    "LOW": [...]
  }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: SecretHunter Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y apktool jadx yara
          pip install -r requirements.txt
      
      - name: Install GitLeaks
        run: |
          wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
          sudo mv gitleaks /usr/local/bin/
      
      - name: Run SecretHunter
        run: python cli.py . --output report.json
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: secrethunter-report
          path: report.json
```

### GitLab CI

```yaml
secrethunter:
  image: python:3.11
  before_script:
    - apt-get update && apt-get install -y apktool jadx yara
    - pip install -r requirements.txt
    - wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
    - tar -xzf gitleaks_8.18.0_linux_x64.tar.gz && mv gitleaks /usr/local/bin/
  script:
    - python cli.py . --output report.json
  artifacts:
    paths:
      - report.json
    expire_in: 1 week
```

## Custom Rules

### Adding Custom Regex Patterns

Edit `rules/regex_patterns.json`:

```json
{
  "patterns": [
    {
      "name": "My Custom API Key",
      "pattern": "MYAPI[0-9A-Za-z]{32}",
      "severity": "HIGH",
      "description": "Custom API key pattern detected"
    }
  ]
}
```

### Adding Custom YARA Rules

Edit `rules/secrets.yar`:

```yara
rule CustomSecret {
    meta:
        description = "Detects my custom secret pattern"
        severity = "HIGH"
    strings:
        $secret = "MYSECRET"
        $pattern = /custom[_-]?key\s*[:=]\s*[a-zA-Z0-9]{20,}/
    condition:
        any of them
}
```

## Best Practices

1. **Scan Early**: Integrate SecretHunter in your CI/CD pipeline
2. **Regular Scans**: Schedule periodic scans of your codebase
3. **Pre-Release**: Always scan APKs before releasing to production
4. **Review Findings**: Manually verify HIGH severity findings
5. **Rotate Secrets**: Immediately rotate any exposed credentials
6. **Use Secret Management**: Store secrets in vault services (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
7. **Git History**: Scan entire Git history to find historical leaks
8. **Custom Rules**: Add organization-specific patterns to detection rules

## Troubleshooting

### APK Decompilation Issues

**Problem**: APK decompilation fails
**Solution**:
- Ensure apktool and jadx are installed and in PATH
- Check APK file is not corrupted
- Try decompiling manually: `apktool d app.apk -o output_dir`

### YARA Compilation Errors

**Problem**: YARA rules syntax errors
**Solution**:
- Validate YARA rules: `yara rules/secrets.yar testfile.txt`
- Simplify complex regex patterns
- Check for proper escaping of special characters

### GitLeaks Not Found

**Problem**: GitLeaks executable not found
**Solution**:
- Install GitLeaks: `sudo apt install gitleaks` or `brew install gitleaks`
- Specify custom path: `--gitleaks-path /path/to/gitleaks`

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new patterns/rules
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [GitLeaks](https://github.com/gitleaks/gitleaks) - Git secret scanning
- [YARA](https://github.com/VirusTotal/yara) - Pattern matching engine
- [Androguard](https://github.com/androguard/androguard) - Android app analysis
- [APKTool](https://github.com/iBotPeaches/Apktool) - APK decompilation
- [JADX](https://github.com/skylot/jadx) - DEX to Java decompiler

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Contact: security@yourcompany.com

---

**⚠️ Security Notice**: SecretHunter is a detection tool. Always follow your organization's security policies when handling discovered secrets. Rotate exposed credentials immediately.
