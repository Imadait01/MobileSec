"""
Suggestion API routes
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
import logging
import asyncio

from models import Vulnerability, SuggestRequest, SuggestResponse, Suggestion
from services import get_suggestion_generator, SuggestionGenerator, get_mongodb_client, get_nova_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/suggest", tags=["Suggestions"])


@router.post(
    "",
    response_model=SuggestResponse,
    summary="Générer des suggestions de correction",
    description="""
    Analyse les vulnérabilités fournies et génère des suggestions de correction
    enrichies par l'IA Amazon Nova 2 Lite via AWS Bedrock.
    
    Chaque suggestion contient:
    - La règle MASVS correspondante
    - Une explication détaillée
    - Un patch de code suggéré
    - Le niveau de confiance
    """,
    responses={
        200: {
            "description": "Suggestions générées avec succès",
            "content": {
                "application/json": {
                    "example": {
                        "suggestions": [
                            {
                                "vulnerability_id": "VULN-001",
                                "masvs_category": "MSTG-CRYPTO-1",
                                "masvs_title": "Utilisation de cryptographie faible",
                                "explanation": "Le code utilise MD5 qui est obsolète...",
                                "suggested_patch": "# Remplacer MD5 par SHA-256\nimport hashlib\nhash = hashlib.sha256(data).hexdigest()",
                                "confidence": 0.95,
                                "references": ["https://owasp.org/..."]
                            }
                        ],
                        "total_processed": 1,
                        "total_suggestions": 1
                    }
                }
            }
        },
        400: {"description": "Requête invalide"},
        500: {"description": "Erreur lors de la génération des suggestions"}
    }
)
async def generate_suggestions(
    request: SuggestRequest,
    generator: SuggestionGenerator = Depends(get_suggestion_generator)
) -> SuggestResponse:
    """
    Génère des suggestions de correction pour une liste de vulnérabilités.
    
    Args:
        request: Liste des vulnérabilités à analyser
        generator: Service de génération de suggestions
        
    Returns:
        SuggestResponse avec les suggestions générées
    """
    try:
        if not request.vulnerabilities:
            raise HTTPException(
                status_code=400,
                detail="La liste des vulnérabilités ne peut pas être vide"
            )
        
        logger.info(f"Traitement de {len(request.vulnerabilities)} vulnérabilités")
        
        suggestions = generator.generate_suggestions(
            vulnerabilities=request.vulnerabilities,
            language=request.language or "java",
            include_patches=request.include_patches
        )
        
        logger.info(f"Généré {len(suggestions)} suggestions")
        
        return SuggestResponse(
            suggestions=suggestions,
            total_processed=len(request.vulnerabilities),
            total_suggestions=len(suggestions)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la génération des suggestions: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la génération des suggestions: {str(e)}"
        )


@router.post(
    "/single",
    response_model=Suggestion,
    summary="Générer une suggestion pour une vulnérabilité",
    description="Analyse une seule vulnérabilité et génère une suggestion de correction."
)
async def generate_single_suggestion(
    vulnerability: Vulnerability,
    generator: SuggestionGenerator = Depends(get_suggestion_generator)
) -> Suggestion:
    """
    Génère une suggestion pour une seule vulnérabilité.
    
    Args:
        vulnerability: La vulnérabilité à analyser
        generator: Service de génération de suggestions
        
    Returns:
        Suggestion de correction
    """
    try:
        logger.info(f"Traitement de la vulnérabilité: {vulnerability.id}")
        
        suggestion = generator.generate_suggestion(vulnerability)
        
        if not suggestion:
            raise HTTPException(
                status_code=404,
                detail="Impossible de générer une suggestion pour cette vulnérabilité"
            )
        
        return suggestion
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la génération de la suggestion: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la génération de la suggestion: {str(e)}"
        )


@router.get(
    "/categories",
    summary="Lister les catégories MASVS supportées",
    description="Retourne la liste des catégories MASVS pour lesquelles des règles sont disponibles."
)
async def list_categories(
    generator: SuggestionGenerator = Depends(get_suggestion_generator)
) -> dict:
    """
    Liste les catégories MASVS disponibles.
    
    Returns:
        Liste des catégories avec le nombre de règles
    """
    try:
        categories = {}
        # rules est un Dict[str, MASVSRule], on itère sur les valeurs
        for rule_id, rule in generator.rule_engine.rules.items():
            # Extraire la catégorie du rule_id (ex: MSTG-CRYPTO-1 -> MSTG-CRYPTO)
            category = "-".join(rule_id.split("-")[:2]) if "-" in rule_id else "Unknown"
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        return {
            "categories": categories,
            "total_rules": len(generator.rule_engine.rules)
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des catégories: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la récupération des catégories: {str(e)}"
        )


# ============================================================================
# NOUVEAUX ENDPOINTS - Lecture depuis MongoDB par scan_id
# ============================================================================

@router.get(
    "/scan/{scan_id}",
    summary="Générer suggestions pour un scan (lit MongoDB)",
    description="""
    Récupère automatiquement les vulnérabilités des 3 microservices 
    (CryptoCheck, SecretHunter, NetworkInspector) depuis MongoDB,
    génère des suggestions en phrases naturelles et les stocke.
    """
)
async def generate_suggestions_for_scan(
    scan_id: str,
    regenerate: bool = Query(False, description="Forcer la régénération même si des suggestions existent")
):
    """
    Génère des suggestions pour un scan complet.
    
    1. Lit les vulnérabilités depuis MongoDB (3 microservices)
    2. Génère des suggestions en phrases naturelles via LLM
    3. Stocke les suggestions dans MongoDB
    
    Args:
        scan_id: Identifiant du scan APK
        regenerate: Forcer la régénération
        
    Returns:
        Suggestions en phrases naturelles
    """
    mongo_client = get_mongodb_client()
    nova_client = get_nova_client()
    
    # Vérifier la connexion MongoDB
    if not mongo_client.is_connected:
        raise HTTPException(
            status_code=503,
            detail="MongoDB non disponible"
        )
    
    # Vérifier si des suggestions existent déjà
    if not regenerate:
        existing = mongo_client.get_suggestions(scan_id)
        if existing and existing.get("suggestions"):
            logger.info(f"✅ Suggestions existantes trouvées pour scan {scan_id}")
            return {
                "status": "cached",
                "scan_id": scan_id,
                "message": "Suggestions déjà générées (utilisez regenerate=true pour forcer)",
                "suggestions_count": existing.get("suggestions_count", 0),
                "suggestions": existing.get("suggestions", []),
                "generated_at": existing.get("generated_at"),
                "model_used": existing.get("model_used")
            }
    
    # Récupérer toutes les vulnérabilités des 3 microservices
    logger.info(f"🔍 Récupération des vulnérabilités pour scan {scan_id}")
    vuln_data = mongo_client.get_all_vulnerabilities(scan_id)
    
    if vuln_data["total"] == 0:
        return {
            "status": "no_vulnerabilities",
            "scan_id": scan_id,
            "message": "Aucune vulnérabilité trouvée pour ce scan",
            "by_tool": vuln_data["by_tool"],
            "suggestions": []
        }
    
    # Générer les suggestions en phrases naturelles
    logger.info(f"🤖 Génération de {vuln_data['total']} suggestions...")
    
    suggestions = []
    for vuln in vuln_data["vulnerabilities"]:
        try:
            suggestion = await nova_client.generate_natural_suggestion_async(vuln)
            suggestions.append(suggestion)
        except Exception as e:
            logger.error(f"❌ Erreur génération suggestion pour {vuln.get('id')}: {e}")
            # Ajouter une suggestion fallback
            suggestions.append(nova_client._generate_natural_fallback(vuln))
    
    # Sauvegarder dans MongoDB
    model_used = nova_client.model if nova_client.is_configured else "fallback"
    mongo_client.save_suggestions(scan_id, suggestions, model_used)
    
    logger.info(f"✅ {len(suggestions)} suggestions générées et sauvegardées pour scan {scan_id}")
    
    return {
        "status": "success",
        "scan_id": scan_id,
        "message": f"{len(suggestions)} suggestions générées avec succès",
        "vulnerabilities_by_tool": vuln_data["by_tool"],
        "suggestions_count": len(suggestions),
        "suggestions": suggestions,
        "model_used": model_used
    }


@router.get(
    "/scan/{scan_id}/vulnerabilities",
    summary="Voir les vulnérabilités d'un scan (sans générer)",
    description="Affiche les vulnérabilités des 3 microservices sans générer de suggestions."
)
async def get_scan_vulnerabilities(scan_id: str):
    """
    Récupère les vulnérabilités d'un scan depuis MongoDB.
    Utile pour voir ce qui sera analysé avant de générer.
    """
    mongo_client = get_mongodb_client()
    
    if not mongo_client.is_connected:
        raise HTTPException(status_code=503, detail="MongoDB non disponible")
    
    vuln_data = mongo_client.get_all_vulnerabilities(scan_id)
    scan_info = mongo_client.get_scan_info(scan_id)
    
    return {
        "scan_id": scan_id,
        "app_info": scan_info,
        "total_vulnerabilities": vuln_data["total"],
        "by_tool": vuln_data["by_tool"],
        "vulnerabilities": vuln_data["vulnerabilities"]
    }


@router.get(
    "/scan/{scan_id}/cached",
    summary="Récupérer les suggestions en cache",
    description="Récupère les suggestions déjà générées sans en créer de nouvelles."
)
async def get_cached_suggestions(scan_id: str):
    """
    Récupère les suggestions déjà stockées dans MongoDB.
    Ne génère pas de nouvelles suggestions.
    """
    mongo_client = get_mongodb_client()
    
    if not mongo_client.is_connected:
        raise HTTPException(status_code=503, detail="MongoDB non disponible")
    
    existing = mongo_client.get_suggestions(scan_id)
    
    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune suggestion trouvée pour le scan {scan_id}. Utilisez GET /scan/{scan_id} pour générer."
        )
    
    return {
        "status": "cached",
        "scan_id": scan_id,
        "suggestions_count": existing.get("suggestions_count", 0),
        "suggestions": existing.get("suggestions", []),
        "generated_at": existing.get("generated_at"),
        "model_used": existing.get("model_used")
    }
