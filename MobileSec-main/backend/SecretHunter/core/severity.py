"""
Severity Module
Handles severity classification and risk scoring.
"""

from typing import List, Dict, Any
from collections import Counter


class SeverityClassifier:
    """Classifies findings by severity and calculates risk scores."""
    
    # Mapping des sévérités vers des scores numériques
    SEVERITY_SCORES = {
        'HIGH': 10,
        'MEDIUM': 5,
        'LOW': 1
    }
    
    # Règles de classification basées sur le type de secret
    HIGH_SEVERITY_KEYWORDS = [
        'api key', 'access key', 'secret key', 'private key',
        'oauth', 'token', 'jwt', 'password', 'credential',
        'database', 'connection string', 'rsa', 'dsa', 'ec'
    ]
    
    MEDIUM_SEVERITY_KEYWORDS = [
        'certificate', 'endpoint', 'url', 'config', 'secret'
    ]
    
    def __init__(self):
        """Initialize the severity classifier."""
        pass
    
    def classify_finding(self, finding: Dict[str, Any]) -> str:
        """
        Classify a finding's severity.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Severity level (HIGH, MEDIUM, LOW)
        """
        # Si la sévérité est déjà définie, l'utiliser
        existing_severity = finding.get('severity')
        if existing_severity in ['HIGH', 'MEDIUM', 'LOW']:
            return existing_severity
        
        # Sinon, classifier basé sur le nom de la règle et la description
        rule_name = finding.get('rule_name', '').lower()
        description = finding.get('description', '').lower()
        match_text = finding.get('match', '').lower()
        
        combined_text = f"{rule_name} {description} {match_text}"
        
        # Vérifier les mots-clés HIGH
        if any(keyword in combined_text for keyword in self.HIGH_SEVERITY_KEYWORDS):
            return 'HIGH'
        
        # Vérifier les mots-clés MEDIUM
        if any(keyword in combined_text for keyword in self.MEDIUM_SEVERITY_KEYWORDS):
            return 'MEDIUM'
        
        # Par défaut, LOW
        return 'LOW'
    
    def calculate_risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall risk score from findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with risk score and breakdown
        """
        if not findings:
            return {
                'total_score': 0,
                'max_score': 0,
                'risk_level': 'NONE',
                'severity_breakdown': {
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
            }
        
        # Classifier toutes les findings
        classified_findings = []
        for finding in findings:
            severity = self.classify_finding(finding)
            finding['severity'] = severity
            classified_findings.append(finding)
        
        # Compter par sévérité
        severity_counts = Counter(finding['severity'] for finding in classified_findings)
        
        # Calculer le score total
        total_score = sum(
            self.SEVERITY_SCORES.get(severity, 0) * count
            for severity, count in severity_counts.items()
        )
        
        # Score maximum possible (si tout était HIGH)
        max_score = len(findings) * self.SEVERITY_SCORES['HIGH']
        
        # Niveau de risque basé sur le score
        if total_score == 0:
            risk_level = 'NONE'
        elif total_score >= max_score * 0.7:
            risk_level = 'CRITICAL'
        elif total_score >= max_score * 0.5:
            risk_level = 'HIGH'
        elif total_score >= max_score * 0.3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_score': total_score,
            'max_score': max_score,
            'risk_level': risk_level,
            'severity_breakdown': {
                'HIGH': severity_counts.get('HIGH', 0),
                'MEDIUM': severity_counts.get('MEDIUM', 0),
                'LOW': severity_counts.get('LOW', 0)
            },
            'total_findings': len(findings)
        }
    
    def update_findings_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Update all findings with classified severity.
        
        Args:
            findings: List of findings
            
        Returns:
            List of findings with updated severity
        """
        updated_findings = []
        for finding in findings:
            severity = self.classify_finding(finding)
            finding['severity'] = severity
            updated_findings.append(finding)
        
        return updated_findings

