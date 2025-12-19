#!/usr/bin/env python3
"""
SecretHunter CLI
Command-line interface for SecretHunter security scanning tool.
Supports scanning of source code, mobile apps (APK), and Git repositories.
"""

import argparse
import sys
from pathlib import Path

from core.file_scanner import FileScanner
from core.git_scanner import GitScanner
from core.yara_scanner import YaraScanner
from core.aggregator import ResultAggregator
from core.apk_decompiler import APKDecompiler, is_apk_file


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SecretHunter - DevSecOps tool to detect exposed secrets in software projects',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py /path/to/project
  python cli.py /path/to/project --no-git
  python cli.py /path/to/project --no-yara
  python cli.py /path/to/project --output custom_report.json
        """
    )
    
    parser.add_argument(
        'project_path',
        type=str,
        help='Path to the project directory or APK file to scan'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='output/secrethunter_report.json',
        help='Output path for the report JSON file (default: output/secrethunter_report.json)'
    )
    
    parser.add_argument(
        '--no-git',
        action='store_true',
        help='Skip Git history scanning (GitLeaks)'
    )
    
    parser.add_argument(
        '--no-yara',
        action='store_true',
        help='Skip YARA rules scanning'
    )
    
    parser.add_argument(
        '--no-file-scan',
        action='store_true',
        help='Skip file regex scanning'
    )
    
    parser.add_argument(
        '--gitleaks-path',
        type=str,
        default='gitleaks',
        help='Path to gitleaks executable (default: gitleaks)'
    )
    
    parser.add_argument(
        '--rules-path',
        type=str,
        default='rules/regex_patterns.json',
        help='Path to regex patterns JSON file (default: rules/regex_patterns.json)'
    )
    
    parser.add_argument(
        '--yara-rules-path',
        type=str,
        default='rules/secrets.yar',
        help='Path to YARA rules file (default: rules/secrets.yar)'
    )
    
    args = parser.parse_args()
    
    # Vérifier que le chemin du projet existe
    project_path = Path(args.project_path)
    if not project_path.exists():
        print(f"Error: Project path does not exist: {args.project_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("SecretHunter - Mobile & DevSecOps Security Scanner")
    print("=" * 60)
    print(f"Target: {args.project_path}\n")
    
    # Check if input is an APK file
    decompiler = None
    scan_paths = []
    
    if project_path.is_file() and is_apk_file(str(project_path)):
        print("[APK DETECTED] Starting APK decompilation...\n")
        try:
            decompiler = APKDecompiler(str(project_path))
            decompiled_dir = decompiler.decompile()
            
            if decompiled_dir:
                # Get all scannable paths from decompilation
                scan_paths = decompiler.get_scannable_paths()
                if not scan_paths:
                    scan_paths = [decompiled_dir]
                print(f"\n[APK] Will scan {len(scan_paths)} decompiled directories")
            else:
                print("\n[ERROR] APK decompilation failed. Cannot proceed.")
                sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] APK processing failed: {e}")
            sys.exit(1)
    elif project_path.is_dir():
        # Regular directory scan
        scan_paths = [project_path]
        print(f"Scanning directory: {project_path}\n")
    else:
        print(f"Error: Path must be a directory or APK file: {args.project_path}")
        sys.exit(1)
    
    # Initialiser l'agrégateur
    aggregator = ResultAggregator()
    
    # Scan all paths (for APK, this will be multiple decompiled directories)
    for idx, scan_path in enumerate(scan_paths):
        if len(scan_paths) > 1:
            print(f"\n>>> Scanning path {idx+1}/{len(scan_paths)}: {scan_path.name}")
        
        # 1. Scan des fichiers avec regex
        if not args.no_file_scan:
            print("\n[1/3] Scanning files with regex patterns...")
            file_scanner = FileScanner(rules_path=args.rules_path)
            file_findings = file_scanner.scan_directory(str(scan_path))
            aggregator.add_findings(file_findings, 'file_scanner')
            print(f"File scan completed. Found {len(file_findings)} potential secrets.")
        else:
            print("\n[1/3] File scanning skipped (--no-file-scan)")
        
        # 2. Scan Git avec GitLeaks (only for non-APK or original directory)
        if not args.no_git and scan_path == project_path:
            print("\n[2/3] Scanning Git history with GitLeaks...")
            git_scanner = GitScanner(gitleaks_path=args.gitleaks_path)
            git_findings = git_scanner.scan_repository(str(scan_path))
            aggregator.add_findings(git_findings, 'git_scanner')
        else:
            if args.no_git:
                print("\n[2/3] Git scanning skipped (--no-git)")
            else:
                print("\n[2/3] Git scanning skipped (not applicable for decompiled APK)")
        
        # 3. Scan YARA
        if not args.no_yara:
            print("\n[3/3] Scanning files with YARA rules...")
            yara_scanner = YaraScanner(rules_path=args.yara_rules_path)
            yara_findings = yara_scanner.scan_directory(str(scan_path))
            aggregator.add_findings(yara_findings, 'yara_scanner')
        else:
            print("\n[3/3] YARA scanning skipped (--no-yara)")
    
    # Générer le rapport final
    print("\n" + "=" * 60)
    print("Generating final report...")
    print("=" * 60)
    
    report = aggregator.generate_report(output_path=args.output)
    
    # Afficher un résumé
    summary = report['summary']
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total Findings: {summary['total_findings']}")
    print(f"  - HIGH Severity: {summary['high_severity']}")
    print(f"  - MEDIUM Severity: {summary['medium_severity']}")
    print(f"  - LOW Severity: {summary['low_severity']}")
    print(f"\nRisk Level: {summary['risk_score']['risk_level']}")
    print(f"Risk Score: {summary['risk_score']['total_score']}/{summary['risk_score']['max_score']}")
    print("=" * 60)
    
    # Code de sortie basé sur le niveau de risque
    if summary['high_severity'] > 0:
        sys.exit(1)  # Exit avec erreur si des secrets HIGH sont trouvés
    elif summary['medium_severity'] > 0:
        sys.exit(0)  # Exit avec succès mais avec warnings
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

