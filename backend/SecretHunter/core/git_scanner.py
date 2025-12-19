"""
Git Scanner Module
Wrapper for GitLeaks to scan Git history for secrets.
"""

import subprocess
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional


class GitScanner:
    """Scans Git repository history using GitLeaks."""
    
    def __init__(self, gitleaks_path: str = "gitleaks"):
        """
        Initialize the Git scanner.
        
        Args:
            gitleaks_path: Path to gitleaks executable or 'gitleaks' if in PATH
        """
        self.gitleaks_path = gitleaks_path
        self.results = []
    
    def _check_gitleaks_available(self) -> bool:
        """Check if GitLeaks is available."""
        try:
            result = subprocess.run(
                [self.gitleaks_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def _run_gitleaks(self, repo_path: str) -> Optional[str]:
        """
        Run GitLeaks on the repository.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            JSON output from GitLeaks or None if error
        """
        if not Path(repo_path).exists():
            print(f"Error: Repository path does not exist: {repo_path}")
            return None
        
        # Vérifier si c'est un repo Git
        git_dir = Path(repo_path) / '.git'
        if not git_dir.exists() and not Path(repo_path).is_file():
            print(f"Warning: {repo_path} does not appear to be a Git repository")
            return None
        
        try:
            # Créer un fichier temporaire pour le rapport JSON
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                report_path = tmp_file.name
            
            # Exécuter gitleaks
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=repo_path
            )
            
            # Lire le fichier de rapport
            try:
                if os.path.exists(report_path):
                    with open(report_path, 'r', encoding='utf-8') as f:
                        output = f.read()
                    # Supprimer le fichier temporaire
                    os.unlink(report_path)
                    return output
                else:
                    # Si pas de fichier, essayer stdout
                    if result.returncode in [0, 1]:
                        return result.stdout
                    return None
            except Exception as e:
                print(f"Error reading GitLeaks report: {e}")
                # Essayer stdout en fallback
                if result.returncode in [0, 1]:
                    return result.stdout
                return None
        
        except subprocess.TimeoutExpired:
            print("Error: GitLeaks execution timed out")
            return None
        except FileNotFoundError:
            print(f"Error: GitLeaks not found at '{self.gitleaks_path}'. Please install GitLeaks.")
            return None
        except Exception as e:
            print(f"Error running GitLeaks: {e}")
            return None
    
    def _parse_gitleaks_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse GitLeaks JSON output and convert to standard format.
        
        Args:
            output: JSON output from GitLeaks
            
        Returns:
            List of findings in standard format
        """
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            gitleaks_data = json.loads(output)
            
            # GitLeaks retourne une liste de findings
            if isinstance(gitleaks_data, list):
                for item in gitleaks_data:
                    finding = self._convert_gitleaks_finding(item)
                    if finding:
                        findings.append(finding)
            elif isinstance(gitleaks_data, dict):
                # Parfois GitLeaks retourne un objet avec une clé 'findings'
                if 'findings' in gitleaks_data:
                    for item in gitleaks_data['findings']:
                        finding = self._convert_gitleaks_finding(item)
                        if finding:
                            findings.append(finding)
                else:
                    # Traiter comme un seul finding
                    finding = self._convert_gitleaks_finding(gitleaks_data)
                    if finding:
                        findings.append(finding)
        
        except json.JSONDecodeError as e:
            print(f"Error parsing GitLeaks output: {e}")
            print(f"Output: {output[:500]}")
        
        return findings
    
    def _convert_gitleaks_finding(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert GitLeaks finding to standard format.
        
        Args:
            item: GitLeaks finding object
            
        Returns:
            Finding in standard format or None
        """
        try:
            # Mapping des champs GitLeaks vers notre format
            rule_id = item.get('RuleID', 'unknown')
            description = item.get('Description', '')
            file_path = item.get('File', '')
            line_number = item.get('StartLine', 0)
            match = item.get('Secret', '')
            commit = item.get('Commit', '')
            
            # Déterminer la sévérité basée sur le RuleID
            severity = self._determine_severity(rule_id)
            
            finding = {
                'type': 'gitleaks',
                'rule_name': rule_id,
                'severity': severity,
                'file_path': file_path,
                'line_number': line_number,
                'match': match[:100],  # Limiter la taille
                'commit': commit,
                'description': description
            }
            
            return finding
        
        except Exception as e:
            print(f"Error converting GitLeaks finding: {e}")
            return None
    
    def _determine_severity(self, rule_id: str) -> str:
        """Determine severity based on GitLeaks rule ID."""
        rule_id_lower = rule_id.lower()
        
        high_keywords = ['api', 'key', 'token', 'secret', 'password', 'private', 'credential']
        medium_keywords = ['endpoint', 'url', 'certificate']
        
        if any(keyword in rule_id_lower for keyword in high_keywords):
            return 'HIGH'
        elif any(keyword in rule_id_lower for keyword in medium_keywords):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def scan_repository(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan Git repository for secrets in history.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            List of findings
        """
        self.results = []
        
        if not self._check_gitleaks_available():
            print("Warning: GitLeaks is not available. Skipping Git history scan.")
            print("Please install GitLeaks: https://github.com/gitleaks/gitleaks")
            return []
        
        print(f"Scanning Git repository: {repo_path}")
        
        output = self._run_gitleaks(repo_path)
        if output:
            self.results = self._parse_gitleaks_output(output)
            print(f"Git scan completed. Found {len(self.results)} potential secrets in history.")
        else:
            print("Git scan completed with no results or errors.")
        
        return self.results
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get scan results."""
        return self.results

