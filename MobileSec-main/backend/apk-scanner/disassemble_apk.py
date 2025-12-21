#!/usr/bin/env python3
"""
Script pour désassembler un APK et exporter toutes les informations en JSON
"""
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Ajouter le répertoire src au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from utils.androguard_wrapper import AndroguardWrapper
from utils.permissions_analyzer import PermissionsAnalyzer


def disassemble_apk_to_json(apk_path, output_json=None):
    """
    Désassemble un APK et exporte toutes les informations en JSON
    
    Args:
        apk_path (str): Chemin vers le fichier APK
        output_json (str): Chemin du fichier JSON de sortie (optionnel)
    
    Returns:
        dict: Données complètes de l'APK
    """
    print("=" * 70)
    print("🔍 Désassemblage APK vers JSON")
    print("=" * 70)
    
    if not Path(apk_path).exists():
        print(f"❌ Fichier APK non trouvé: {apk_path}")
        return None
    
    print(f"\n📱 Analyse de: {apk_path}")
    
    try:
        # Charger l'APK avec Androguard
        print("\n⏳ Chargement de l'APK avec Androguard...")
        androguard = AndroguardWrapper(apk_path)
        androguard.load_apk()
        
        # Récupérer les informations de base
        print("📊 Extraction des informations de base...")
        app_info = androguard.get_basic_info()
        
        # Analyser les permissions
        print("🔐 Analyse des permissions...")
        perm_analyzer = PermissionsAnalyzer()
        permissions_analysis = perm_analyzer.analyze_permissions(
            app_info.get('permissions', [])
        )
        
        # Récupérer les informations du certificat
        print("📜 Extraction des informations du certificat...")
        try:
            cert_info = androguard.get_certificate_info()
        except Exception as e:
            print(f"⚠️  Certificat non disponible: {e}")
            cert_info = {}
        
        # Analyser les activités
        print("🎯 Analyse des composants...")
        activities = app_info.get('activities', [])
        services = app_info.get('services', [])
        receivers = app_info.get('receivers', [])
        providers = app_info.get('providers', [])
        
        # Créer la structure JSON complète
        apk_data = {
            "metadata": {
                "apk_path": str(apk_path),
                "apk_name": Path(apk_path).name,
                "analysis_date": datetime.now().isoformat(),
                "file_size": Path(apk_path).stat().st_size,
                "file_size_mb": round(Path(apk_path).stat().st_size / (1024 * 1024), 2)
            },
            "application": {
                "package_name": app_info.get('package_name'),
                "app_name": app_info.get('app_name'),
                "version_code": app_info.get('version_code'),
                "version_name": app_info.get('version_name'),
                "main_activity": app_info.get('main_activity')
            },
            "sdk": {
                "min_sdk": app_info.get('min_sdk'),
                "target_sdk": app_info.get('target_sdk'),
                "max_sdk": app_info.get('max_sdk')
            },
            "signature": {
                "is_signed": app_info.get('is_signed'),
                "is_signed_v1": app_info.get('is_signed_v1'),
                "is_signed_v2": app_info.get('is_signed_v2'),
                "is_signed_v3": app_info.get('is_signed_v3'),
                "certificates": cert_info.get('certificates', [])
            },
            "permissions": {
                "total_count": len(app_info.get('permissions', [])),
                "all_permissions": app_info.get('permissions', []),
                "dangerous_permissions": permissions_analysis.get('dangerous_permissions', []),
                "normal_permissions": permissions_analysis.get('normal_permissions', []),
                "signature_permissions": permissions_analysis.get('signature_permissions', []),
                "analysis": {
                    "dangerous_count": len(permissions_analysis.get('dangerous_permissions', [])),
                    "normal_count": len(permissions_analysis.get('normal_permissions', [])),
                    "signature_count": len(permissions_analysis.get('signature_permissions', []))
                }
            },
            "components": {
                "activities": {
                    "count": len(activities),
                    "list": activities
                },
                "services": {
                    "count": len(services),
                    "list": services
                },
                "receivers": {
                    "count": len(receivers),
                    "list": receivers
                },
                "providers": {
                    "count": len(providers),
                    "list": providers
                }
            },
            "libraries": {
                "count": len(app_info.get('libraries', [])),
                "list": app_info.get('libraries', [])
            },
            "files": {
                "total_count": app_info.get('file_count', 0),
                "files_list": app_info.get('files', [])
            }
        }
        
        # Déterminer le nom du fichier de sortie
        if output_json is None:
            apk_name = Path(apk_path).stem
            output_json = f"output/{apk_name}_disassembled.json"
        
        # Créer le répertoire de sortie si nécessaire
        Path(output_json).parent.mkdir(parents=True, exist_ok=True)
        
        # Sauvegarder en JSON
        print(f"\n💾 Sauvegarde des données dans: {output_json}")
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(apk_data, f, indent=2, ensure_ascii=False)
        
        # Afficher un résumé
        print("\n" + "=" * 70)
        print("✅ Désassemblage terminé avec succès!")
        print("=" * 70)
        print(f"\n📊 Résumé:")
        print(f"  • Package: {apk_data['application']['package_name']}")
        print(f"  • Version: {apk_data['application']['version_name']} ({apk_data['application']['version_code']})")
        print(f"  • Taille: {apk_data['metadata']['file_size_mb']} MB")
        print(f"  • Permissions: {apk_data['permissions']['total_count']}")
        print(f"    - Dangereuses: {apk_data['permissions']['analysis']['dangerous_count']}")
        print(f"  • Composants:")
        print(f"    - Activities: {apk_data['components']['activities']['count']}")
        print(f"    - Services: {apk_data['components']['services']['count']}")
        print(f"    - Receivers: {apk_data['components']['receivers']['count']}")
        print(f"    - Providers: {apk_data['components']['providers']['count']}")
        print(f"  • Librairies: {apk_data['libraries']['count']}")
        print(f"  • Fichiers: {apk_data['files']['total_count']}")
        print(f"\n📄 Fichier JSON: {output_json}")
        print("=" * 70)
        
        return apk_data
        
    except Exception as e:
        print(f"\n❌ Erreur lors du désassemblage: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Point d'entrée principal"""
    if len(sys.argv) < 2:
        print("Usage: python disassemble_apk.py <chemin_apk> [output.json]")
        print("\nExemple:")
        print("  python disassemble_apk.py test-apk/ApiDemos-debug.apk")
        print("  python disassemble_apk.py test-apk/ApiDemos-debug.apk output/my_analysis.json")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    output_json = sys.argv[2] if len(sys.argv) > 2 else None
    
    result = disassemble_apk_to_json(apk_path, output_json)
    
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
