"""
File Scanner Module
Scans files recursively using regex patterns to detect secrets.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any


class FileScanner:
    """Scans files for secrets using regex patterns."""
    
    # Extensions de fichiers à scanner (incluant formats mobiles)
    SCANNABLE_EXTENSIONS = {
        # Source code
        '.py', '.js', '.java', '.ts', '.tsx', '.jsx', '.go', '.rb', '.php',
        '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.kt', '.kts', '.m', '.mm',
        # Android/Mobile specific
        '.smali', '.xml', '.json', '.properties', '.gradle', '.pro',
        # Config files
        '.env', '.config', '.conf', '.yaml', '.yml', '.toml', '.ini',
        # Scripts
        '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
        # Other
        '.sql', '.md', '.txt', '.log', '.plist', '.strings', '.xcconfig'
    }
    
    # Dossiers à ignorer
    IGNORE_DIRS = {
        '.git', '.svn', '.hg', '__pycache__', 'node_modules', '.venv', 'venv',
        'env', '.env', 'dist', 'build', '.idea', '.vscode', 'target', 'bin', 'obj',
        'output'  # Exclure le dossier output pour éviter de scanner les rapports générés
    }
    
    # Fichiers à ignorer
    IGNORE_FILES = {
        '.gitignore', '.gitattributes', '.DS_Store', 'Thumbs.db'
    }
    
    def __init__(self, rules_path: str = "rules/regex_patterns.json"):
        """Initialize the file scanner with regex patterns."""
        self.patterns = self._load_patterns(rules_path)
        self.results = []
    
    def _load_patterns(self, rules_path: str) -> List[Dict[str, Any]]:
        """Load regex patterns from JSON file."""
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('patterns', [])
        except FileNotFoundError:
            print(f"Warning: Rules file not found: {rules_path}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing rules file: {e}")
            return []
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Ignorer les fichiers dans les dossiers ignorés
        for part in file_path.parts:
            if part in self.IGNORE_DIRS:
                return False
        
        # Ignorer les fichiers spécifiques
        if file_path.name in self.IGNORE_FILES:
            return False
        
        # Vérifier l'extension
        if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
            return True
        
        # Scanner les fichiers sans extension si c'est un fichier de config connu
        config_files = {
            '.env', '.env.local', '.env.production', '.env.development',
            'config', 'secrets', 'credentials',
            'AndroidManifest', 'Info', 'Podfile', 'Cartfile'
        }
        if file_path.name in config_files or any(file_path.name.startswith(cf) for cf in config_files):
            return True
        
        # Scanner les fichiers de strings Android/iOS (all_strings.txt, etc.)
        if 'string' in file_path.name.lower() or 'manifest' in file_path.name.lower():
            return True
        
        return False
    
    def _read_file_safely(self, file_path: Path) -> str:
        """Read file content safely, handling encoding errors."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return ""
    
    def _scan_file_content(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Scan file content for secrets using regex patterns."""
        findings = []
        
        lines = content.split('\n')
        
        for pattern_info in self.patterns:
            pattern = pattern_info.get('pattern')
            if not pattern:
                continue
            
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                matches = regex.finditer(content)
                
                for match in matches:
                    # Trouver la ligne du match
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                    
                    finding = {
                        'type': 'regex',
                        'rule_name': pattern_info.get('name', 'Unknown'),
                        'severity': pattern_info.get('severity', 'MEDIUM'),
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'match': match.group(0)[:100],  # Limiter la taille
                        'line_content': line_content.strip()[:200],  # Limiter la taille
                        'description': pattern_info.get('description', '')
                    }
                    findings.append(finding)
            
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{pattern}': {e}")
                continue
        
        return findings
    
    def scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """
        Scan a directory recursively for secrets.
        
        Args:
            directory: Path to the directory to scan
            
        Returns:
            List of findings
        """
        self.results = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(f"Error: Directory does not exist: {directory}")
            return []
        
        if not dir_path.is_dir():
            print(f"Error: Path is not a directory: {directory}")
            return []
        
        print(f"Scanning directory: {directory}")
        
        # Parcourir récursivement
        processed_files = 0
        MAX_FINDINGS_TOTAL = 1000
        MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024 # 1MB

        for file_path in dir_path.rglob('*'):
            if len(self.results) >= MAX_FINDINGS_TOTAL:
                 print(f"Max findings limit ({MAX_FINDINGS_TOTAL}) reached. Stopping scan.")
                 break

            if not file_path.is_file():
                continue
            
            # Skip large files
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                 continue

            if not self._should_scan_file(file_path):
                continue
            
            try:
                processed_files += 1
                content = self._read_file_safely(file_path)
                if content:
                    findings = self._scan_file_content(file_path, content)
                    # Limit per file findings
                    self.results.extend(findings[:50])
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
                continue
        
        print(f"File scan completed. Processed {processed_files} files. Found {len(self.results)} potential secrets.")
        return self.results
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results."""
        return self.results

