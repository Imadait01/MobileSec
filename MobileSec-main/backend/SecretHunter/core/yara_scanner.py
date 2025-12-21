"""
YARA Scanner Module
Scans files using YARA rules to detect secrets.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: yara-python not installed. YARA scanning will be disabled.")


class YaraScanner:
    """Scans files for secrets using YARA rules."""
    
    def __init__(self, rules_path: str = "rules/secrets.yar"):
        """
        Initialize the YARA scanner.
        
        Args:
            rules_path: Path to YARA rules file
        """
        self.rules_path = rules_path
        self.rules = None
        self.results = []
        
        if YARA_AVAILABLE:
            self._load_rules()
        else:
            print("Warning: YARA is not available. Install yara-python to enable YARA scanning.")
    
    def _load_rules(self) -> None:
        """Load YARA rules from file."""
        try:
            rules_file = Path(self.rules_path)
            if not rules_file.exists():
                print(f"Warning: YARA rules file not found: {self.rules_path}")
                return
            
            # Compiler les règles YARA
            self.rules = yara.compile(filepath=str(rules_file))
            print(f"YARA rules loaded from: {self.rules_path}")
        
        except yara.SyntaxError as e:
            print(f"Error: Invalid YARA rules syntax: {e}")
            self.rules = None
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.rules = None
    
    def _read_file_safely(self, file_path: Path) -> bytes:
        """Read file content as bytes for YARA scanning."""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return b""
    
    def _scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Scan a single file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of findings
        """
        findings = []
        
        if not self.rules:
            return findings
        
        try:
            file_content = self._read_file_safely(file_path)
            if not file_content:
                return findings
            
            # Matcher les règles YARA
            matches = self.rules.match(data=file_content)
            
            for match in matches:
                # Extraire la sévérité depuis les métadonnées
                severity = match.meta.get('severity', 'MEDIUM')
                description = match.meta.get('description', match.rule)
                
                # Pour chaque string matché
                for string_match in match.strings:
                    # string_match est un objet StringMatch avec des instances
                    # Chaque instance contient: offset, matched_data
                    if hasattr(string_match, 'instances') and string_match.instances:
                        for instance in string_match.instances:
                            offset = instance.offset
                            matched_data = instance.matched_data
                            
                            line_number = self._get_line_number(file_content, offset)
                            
                            # Décoder les données matchées en string
                            try:
                                match_str = matched_data.decode('utf-8', errors='ignore')[:100]
                            except Exception:
                                match_str = str(matched_data)[:100]
                            
                            finding = {
                                'type': 'yara',
                                'rule_name': match.rule,
                                'severity': severity,
                                'file_path': str(file_path),
                                'line_number': line_number,
                                'match': match_str,
                                'description': description,
                                'source': 'yara_scanner'
                            }
                            findings.append(finding)
        
        except Exception as e:
            print(f"Error scanning file {file_path} with YARA: {e}")
        
        return findings
    
    def _get_line_number(self, content: bytes, offset: int) -> int:
        """Get line number from byte offset."""
        try:
            return content[:offset].count(b'\n') + 1
        except Exception:
            return 0
    
    def scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """
        Scan a directory recursively using YARA rules.
        
        Args:
            directory: Path to the directory to scan
            
        Returns:
            List of findings
        """
        self.results = []
        
        if not YARA_AVAILABLE:
            print("YARA scanning skipped (yara-python not installed)")
            return []
        
        if not self.rules:
            print("YARA scanning skipped (rules not loaded)")
            return []
        
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(f"Error: Directory does not exist: {directory}")
            return []
        
        if not dir_path.is_dir():
            print(f"Error: Path is not a directory: {directory}")
            return []
        
        print(f"Scanning directory with YARA: {directory}")
        
        # Parcourir récursivement
        processed_files = 0
        MAX_FINDINGS_TOTAL = 1000
        MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024 # 1MB

        for file_path in dir_path.rglob('*'):
            if len(self.results) >= MAX_FINDINGS_TOTAL:
                 print(f"Max YARA findings limit ({MAX_FINDINGS_TOTAL}) reached. Stopping scan.")
                 break

            if not file_path.is_file():
                continue
            
            # Ignorer les fichiers binaires trop gros (> 1MB)
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except Exception:
                continue
            
            try:
                processed_files += 1
                findings = self._scan_file(file_path)
                # Limit per file findings
                self.results.extend(findings[:50])
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
                continue
        
        print(f"YARA scan completed. Processed {processed_files} files. Found {len(self.results)} potential secrets.")
        return self.results
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results."""
        return self.results

