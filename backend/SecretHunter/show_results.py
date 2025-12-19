#!/usr/bin/env python3
"""Affiche les résultats du scan de manière lisible."""

import json
import sys

def main():
    report_path = "output/secrethunter_report.json"
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Erreur: Fichier de rapport non trouvé: {report_path}")
        sys.exit(1)
    
    summary = data['summary']
    findings = data['findings']
    
    print("=" * 70)
    print("RESULTATS DU SCAN SECRETHUNTER")
    print("=" * 70)
    print(f"\nResume:")
    print(f"   Total de findings: {summary['total_findings']}")
    print(f"   - HIGH:   {summary['high_severity']}")
    print(f"   - MEDIUM: {summary['medium_severity']}")
    print(f"   - LOW:    {summary['low_severity']}")
    print(f"\nScore de risque: {summary['risk_score']['risk_level']}")
    print(f"   Score: {summary['risk_score']['total_score']}/{summary['risk_score']['max_score']}")
    
    if findings:
        print("\n" + "=" * 70)
        print("DETAILS DES FINDINGS")
        print("=" * 70)
        
        for i, finding in enumerate(findings, 1):
            severity_marker = {
                'HIGH': '[!!!]',
                'MEDIUM': '[!!]',
                'LOW': '[!]'
            }.get(finding['severity'], '[?]')
            
            print(f"\n{i}. {severity_marker} [{finding['severity']}] {finding['rule_name']}")
            print(f"   Fichier: {finding['file_path']}")
            print(f"   Ligne: {finding['line_number']}")
            print(f"   Match: {finding['match'][:60]}...")
            print(f"   Description: {finding['description']}")
            print(f"   Source: {finding['source']}")
    else:
        print("\n✅ Aucun secret détecté!")

if __name__ == '__main__':
    main()

