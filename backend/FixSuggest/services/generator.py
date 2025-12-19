"""
FixSuggest - Suggestion Generator
==================================
Combine les règles MASVS et les suggestions LLM pour produire le résultat final.
"""

import logging
from typing import List, Optional
from datetime import datetime

from models import Vulnerability, Suggestion, MASVSRule
from services.rule_engine import get_rule_engine
from services.llm_suggester import get_nova_client

logger = logging.getLogger(__name__)


class SuggestionGenerator:
    """
    Générateur de suggestions de correction.
    Combine le matching MASVS et l'enrichissement LLM.
    """
    
    def __init__(self):
        """
        Initialise le générateur.
        """
        self.rule_engine = get_rule_engine()
        self.nova_client = get_nova_client()
    
    def generate_suggestion(
        self,
        vulnerability: Vulnerability,
        language: str = "java",
        include_patch: bool = True
    ) -> Suggestion:
        """
        Génère une suggestion de correction pour une vulnérabilité.
        
        Args:
            vulnerability: La vulnérabilité à analyser
            language: Langage de programmation cible
            include_patch: Inclure un patch de code
            
        Returns:
            Suggestion de correction complète
        """
        logger.debug(f"Generating suggestion for vulnerability: {vulnerability.id}")
        
        # 1. Trouver les règles MASVS correspondantes
        matching_rules = self.rule_engine.find_matching_rules(vulnerability)
        
        # Prendre la première règle la plus pertinente
        masvs_rule: Optional[MASVSRule] = matching_rules[0] if matching_rules else None
        
        if masvs_rule:
            logger.debug(f"Matched MASVS rule: {masvs_rule.rule_id}")
        else:
            logger.debug("No MASVS rule matched, using generic recommendation")
        
        # 2. Générer la suggestion via LLM
        llm_result = self.nova_client.generate_suggestion(
            vulnerability=vulnerability,
            masvs_rule=masvs_rule,
            language=language
        )
        
        # 3. Construire la suggestion finale
        suggestion = Suggestion(
            vulnerability_id=vulnerability.id,
            vulnerability_title=vulnerability.title,
            
            # Règle MASVS
            masvs_rule_id=masvs_rule.rule_id if masvs_rule else None,
            masvs_rule_title=masvs_rule.title if masvs_rule else None,
            
            # Recommandations
            original_recommendation=masvs_rule.recommendation if masvs_rule else None,
            enriched_recommendation=llm_result.get("recommendation", ""),
            
            # Patch de code
            patch_code=llm_result.get("patch_code", "") if include_patch else None,
            patch_language=language if include_patch and llm_result.get("patch_code") else None,
            
            # Métadonnées
            confidence=0.95 if masvs_rule and self.nova_client.is_configured else 0.7,
            references=masvs_rule.references if masvs_rule else []
        )
        
        return suggestion
    
    def generate_suggestions(
        self,
        vulnerabilities: List[Vulnerability],
        language: str = "java",
        include_patches: bool = True
    ) -> List[Suggestion]:
        """
        Génère des suggestions pour une liste de vulnérabilités.
        
        Args:
            vulnerabilities: Liste des vulnérabilités
            language: Langage de programmation cible
            include_patches: Inclure les patches de code
            
        Returns:
            Liste des suggestions
        """
        suggestions = []
        
        for i, vuln in enumerate(vulnerabilities):
            logger.info(f"Processing vulnerability {i+1}/{len(vulnerabilities)}: {vuln.id}")
            
            try:
                suggestion = self.generate_suggestion(
                    vulnerability=vuln,
                    language=language,
                    include_patch=include_patches
                )
                suggestions.append(suggestion)
                
            except Exception as e:
                logger.error(f"Error generating suggestion for {vuln.id}: {e}")
                
                # Créer une suggestion d'erreur
                suggestions.append(Suggestion(
                    vulnerability_id=vuln.id,
                    vulnerability_title=vuln.title,
                    enriched_recommendation=f"Erreur lors de la génération: {str(e)}",
                    confidence=0.0
                ))
        
        return suggestions


# Instance globale du générateur
suggestion_generator = SuggestionGenerator()


def get_suggestion_generator() -> SuggestionGenerator:
    """
    Retourne l'instance du générateur de suggestions.
    """
    return suggestion_generator
