#!/usr/bin/env python3
"""
Utilitaire pour visualiser et interroger les fichiers JSON de désassemblage APK
"""
import json
import sys
from pathlib import Path


def load_apk_json(json_path):
    """Charge le fichier JSON de désassemblage"""
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def show_summary(data):
    """Affiche un résumé de l'APK"""
    print("\n" + "=" * 70)
    print("📱 Résumé de l'APK")
    print("=" * 70)
    
    app = data['application']
    meta = data['metadata']
    sdk = data['sdk']
    perms = data['permissions']
    comps = data['components']
    
    print(f"\n📦 Application:")
    print(f"  Nom: {app['app_name']}")
    print(f"  Package: {app['package_name']}")
    print(f"  Version: {app['version_name']} (code: {app['version_code']})")
    print(f"  Activity principale: {app['main_activity']}")
    
    print(f"\n📊 Métadonnées:")
    print(f"  Fichier: {meta['apk_name']}")
    print(f"  Taille: {meta['file_size_mb']} MB")
    print(f"  Date d'analyse: {meta['analysis_date']}")
    
    print(f"\n🔧 SDK:")
    print(f"  Min: {sdk['min_sdk']}")
    print(f"  Target: {sdk['target_sdk']}")
    print(f"  Max: {sdk['max_sdk'] or 'N/A'}")
    
    print(f"\n🔐 Permissions ({perms['total_count']}):")
    print(f"  Dangereuses: {perms['analysis']['dangerous_count']}")
    print(f"  Normales: {perms['analysis']['normal_count']}")
    print(f"  Signature: {perms['analysis']['signature_count']}")
    
    print(f"\n🎯 Composants:")
    print(f"  Activities: {comps['activities']['count']}")
    print(f"  Services: {comps['services']['count']}")
    print(f"  Receivers: {comps['receivers']['count']}")
    print(f"  Providers: {comps['providers']['count']}")
    
    print(f"\n📚 Librairies: {data['libraries']['count']}")
    print(f"📄 Fichiers: {data['files']['total_count']}")
    
    print("=" * 70)


def show_permissions(data):
    """Affiche toutes les permissions"""
    print("\n" + "=" * 70)
    print("🔐 Permissions de l'APK")
    print("=" * 70)
    
    perms = data['permissions']
    
    print(f"\n📋 Toutes les permissions ({perms['total_count']}):")
    for perm in perms['all_permissions']:
        print(f"  • {perm}")
    
    if perms['dangerous_permissions']:
        print(f"\n⚠️  Permissions dangereuses ({perms['analysis']['dangerous_count']}):")
        for perm in perms['dangerous_permissions']:
            print(f"  • {perm['name']}")
            if perm.get('description'):
                print(f"    → {perm['description']}")


def show_components(data, component_type='all'):
    """Affiche les composants"""
    print("\n" + "=" * 70)
    print(f"🎯 Composants de l'APK")
    print("=" * 70)
    
    comps = data['components']
    
    if component_type in ['all', 'activities']:
        print(f"\n📱 Activities ({comps['activities']['count']}):")
        for i, activity in enumerate(comps['activities']['list'][:10], 1):
            print(f"  {i}. {activity}")
        if comps['activities']['count'] > 10:
            print(f"  ... et {comps['activities']['count'] - 10} autres")
    
    if component_type in ['all', 'services']:
        print(f"\n⚙️  Services ({comps['services']['count']}):")
        for service in comps['services']['list']:
            print(f"  • {service}")
    
    if component_type in ['all', 'receivers']:
        print(f"\n📡 Receivers ({comps['receivers']['count']}):")
        for receiver in comps['receivers']['list']:
            print(f"  • {receiver}")
    
    if component_type in ['all', 'providers']:
        print(f"\n📦 Providers ({comps['providers']['count']}):")
        for provider in comps['providers']['list']:
            print(f"  • {provider}")


def show_signature(data):
    """Affiche les informations de signature"""
    print("\n" + "=" * 70)
    print("🔏 Informations de signature")
    print("=" * 70)
    
    sig = data['signature']
    
    print(f"\nSigné: {sig['is_signed']}")
    print(f"Signature V1: {sig['is_signed_v1']}")
    print(f"Signature V2: {sig['is_signed_v2']}")
    print(f"Signature V3: {sig['is_signed_v3']}")
    
    if sig['certificates']:
        print(f"\n📜 Certificats ({len(sig['certificates'])}):")
        for i, cert in enumerate(sig['certificates'], 1):
            print(f"\n  Certificat #{i}:")
            print(f"    Serial: {cert.get('serial_number')}")
            print(f"    Valide du: {cert.get('not_before')}")
            print(f"    Valide jusqu'au: {cert.get('not_after')}")


def search_in_json(data, query):
    """Recherche dans le JSON"""
    print(f"\n🔍 Recherche de: '{query}'\n")
    
    results = []
    query_lower = query.lower()
    
    # Rechercher dans les activities
    for activity in data['components']['activities']['list']:
        if query_lower in activity.lower():
            results.append(('Activity', activity))
    
    # Rechercher dans les services
    for service in data['components']['services']['list']:
        if query_lower in service.lower():
            results.append(('Service', service))
    
    # Rechercher dans les permissions
    for perm in data['permissions']['all_permissions']:
        if query_lower in perm.lower():
            results.append(('Permission', perm))
    
    # Rechercher dans les fichiers
    for file in data['files']['files_list']:
        if query_lower in file.lower():
            results.append(('Fichier', file))
    
    if results:
        print(f"✅ {len(results)} résultat(s) trouvé(s):\n")
        for type_item, item in results[:20]:
            print(f"  [{type_item}] {item}")
        if len(results) > 20:
            print(f"\n  ... et {len(results) - 20} autres résultats")
    else:
        print("❌ Aucun résultat trouvé")


def main():
    """Point d'entrée principal"""
    if len(sys.argv) < 2:
        print("Usage: python view_apk_json.py <fichier.json> [commande]")
        print("\nCommandes disponibles:")
        print("  summary       - Résumé de l'APK (par défaut)")
        print("  permissions   - Liste des permissions")
        print("  components    - Liste des composants")
        print("  activities    - Liste des activities")
        print("  services      - Liste des services")
        print("  signature     - Informations de signature")
        print("  search <term> - Rechercher dans le JSON")
        print("\nExemple:")
        print("  python view_apk_json.py output/ApiDemos-debug_disassembled.json")
        print("  python view_apk_json.py output/ApiDemos-debug_disassembled.json permissions")
        print("  python view_apk_json.py output/ApiDemos-debug_disassembled.json search camera")
        sys.exit(1)
    
    json_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else 'summary'
    
    if not Path(json_path).exists():
        print(f"❌ Fichier non trouvé: {json_path}")
        sys.exit(1)
    
    # Charger le JSON
    data = load_apk_json(json_path)
    
    # Exécuter la commande
    if command == 'summary':
        show_summary(data)
    elif command == 'permissions':
        show_permissions(data)
    elif command == 'components':
        show_components(data, 'all')
    elif command == 'activities':
        show_components(data, 'activities')
    elif command == 'services':
        show_components(data, 'services')
    elif command == 'signature':
        show_signature(data)
    elif command == 'search':
        if len(sys.argv) < 4:
            print("❌ Veuillez fournir un terme de recherche")
            sys.exit(1)
        search_in_json(data, sys.argv[3])
    else:
        print(f"❌ Commande inconnue: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
