"""
Aggregator Module
Merges results from different scanners and removes duplicates.
"""

import json
from typing import List, Dict, Any
from pathlib import Path
from core.severity import SeverityClassifier


class ResultAggregator:
    """Aggregates and deduplicates findings from all scanners."""
    
    def __init__(self):
        """Initialize the aggregator."""
        self.severity_classifier = SeverityClassifier()
        self.all_findings = []
    
    def add_findings(self, findings: List[Dict[str, Any]], source: str) -> None:
        """
        Add findings from a scanner source.
        
        Args:
            findings: List of findings
            source: Source identifier (e.g., 'file_scanner', 'git_scanner', 'yara_scanner')
        """
        for finding in findings:
            finding['source'] = source
            self.all_findings.append(finding)
    
    def _normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a finding for comparison."""
        return {
            'file_path': finding.get('file_path', ''),
            'line_number': finding.get('line_number', 0),
            'match': finding.get('match', '')[:50],  # Normaliser la taille
            'rule_name': finding.get('rule_name', '')
        }
    
    def _are_findings_duplicate(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        """
        Check if two findings are duplicates.
        
        Args:
            finding1: First finding
            finding2: Second finding
            
        Returns:
            True if duplicates, False otherwise
        """
        norm1 = self._normalize_finding(finding1)
        norm2 = self._normalize_finding(finding2)
        
        # Même fichier et même ligne
        if (norm1['file_path'] == norm2['file_path'] and 
            norm1['line_number'] == norm2['line_number']):
            # Vérifier si le match est similaire
            match1 = norm1['match'].lower().strip()
            match2 = norm2['match'].lower().strip()
            
            if match1 and match2:
                # Si les matches sont identiques ou très similaires
                if match1 == match2 or match1 in match2 or match2 in match1:
                    return True
        
        return False
    
    def deduplicate_findings(self) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings, keeping the one with highest severity.
        
        Returns:
            Deduplicated list of findings
        """
        if not self.all_findings:
            return []
        
        # Trier par sévérité (HIGH > MEDIUM > LOW)
        severity_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        # Classifier toutes les findings
        classified_findings = self.severity_classifier.update_findings_severity(self.all_findings)
        
        # Trier par sévérité décroissante
        classified_findings.sort(
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 0),
            reverse=True
        )
        
        unique_findings = []
        seen_normalized = []
        
        for finding in classified_findings:
            is_duplicate = False
            normalized = self._normalize_finding(finding)
            
            # Vérifier contre les findings déjà ajoutés
            for seen_norm in seen_normalized:
                if self._are_findings_duplicate(
                    {**finding, **normalized},
                    {**finding, **seen_norm}
                ):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                unique_findings.append(finding)
                seen_normalized.append(normalized)
        
        return unique_findings
    
    def generate_report(self, output_path: str = "output/secrethunter_report.json") -> Dict[str, Any]:
        """
        Generate final report with aggregated findings.
        
        Args:
            output_path: Path to output JSON file
            
        Returns:
            Report dictionary
        """
        # Dédupliquer les findings
        unique_findings = self.deduplicate_findings()
        
        # Calculer le score de risque
        risk_score = self.severity_classifier.calculate_risk_score(unique_findings)
        
        # Organiser les findings par sévérité
        findings_by_severity = {
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for finding in unique_findings:
            severity = finding.get('severity', 'LOW')
            findings_by_severity[severity].append(finding)
        
        # Créer le rapport final
        report = {
            'summary': {
                'total_findings': len(unique_findings),
                'high_severity': len(findings_by_severity['HIGH']),
                'medium_severity': len(findings_by_severity['MEDIUM']),
                'low_severity': len(findings_by_severity['LOW']),
                'risk_score': risk_score
            },
            'findings': unique_findings,
            'findings_by_severity': findings_by_severity
        }
        
        # Sauvegarder le rapport
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"\nReport saved to: {output_path}")
            print(f"Total findings: {len(unique_findings)}")
            print(f"  - HIGH: {len(findings_by_severity['HIGH'])}")
            print(f"  - MEDIUM: {len(findings_by_severity['MEDIUM'])}")
            print(f"  - LOW: {len(findings_by_severity['LOW'])}")
            print(f"Risk Level: {risk_score['risk_level']}")
            print(f"Risk Score: {risk_score['total_score']}/{risk_score['max_score']}")
        
        except Exception as e:
            print(f"Error saving report: {e}")
        
        return report
    
    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings before deduplication."""
        return self.all_findings

