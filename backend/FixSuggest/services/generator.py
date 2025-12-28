"""
FixSuggest - Suggestion Generator
==================================
Combine les règles MASVS et les suggestions LLM pour produire le résultat final.
"""

import logging
import httpx
from typing import List, Optional, Dict, Any
from datetime import datetime

from config import settings
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
            
            # Recommandations enrichies
            original_recommendation=masvs_rule.recommendation if masvs_rule else None,
            enriched_recommendation=llm_result.get("recommendation", ""),
            analysis=llm_result.get("analysis", ""),
            
            # Code patches détaillés
            patch_code=llm_result.get("patch_code", "") if include_patch else None,
            before_code=llm_result.get("before_code"),
            after_code=llm_result.get("after_code"),
            patch_language=language if include_patch and llm_result.get("patch_code") else None,
            
            # Conseils et références
            additional_tips=llm_result.get("additional_tips", []),
            owasp_references=llm_result.get("owasp_references", []),
            
            # Métadonnées
            confidence=0.95 if masvs_rule and self.nova_client.is_configured else 0.7,
            references=masvs_rule.references if masvs_rule else []
        )
        
        return suggestion
    
    async def _prioritize_with_ml(
        self,
        scan_id: str,
        vulnerabilities: List[Vulnerability]
    ) -> List[Dict[str, Any]]:
        """
        Call ml-model service to prioritize vulnerabilities using LightGBM.
        
        Args:
            scan_id: The scan ID
            vulnerabilities: List of vulnerabilities to prioritize
            
        Returns:
            List of prioritized vulnerability data with confidence scores
        """
        try:
            ml_model_url = settings.ml_model_url if hasattr(settings, 'ml_model_url') else "http://ml-model:8001"
            endpoint = f"{ml_model_url}/api/v1/prioritize"
            
            # Prepare request payload
            vuln_inputs = [
                {
                    "id": vuln.id,
                    "title": vuln.title or "Unknown",
                    "severity": vuln.severity or "MEDIUM",
                    "file": vuln.file,
                    "line": vuln.line,
                    "description": vuln.description
                }
                for vuln in vulnerabilities
            ]
            
            request_payload = {
                "scan_id": scan_id,
                "vulnerabilities": vuln_inputs
            }
            
            logger.info(f"Calling ML model for prioritization: {endpoint}")
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(endpoint, json=request_payload)
                response.raise_for_status()
                result = response.json()
            
            prioritized = result.get("prioritized", [])
            logger.info(f"ML prioritization successful. Top category: {prioritized[0]['lightgbm_category'] if prioritized else 'None'}")
            
            return prioritized
            
        except httpx.HTTPError as e:
            logger.warning(f"ML prioritization failed (HTTP error): {e}. Falling back to severity-based sorting.")
            return []
        except Exception as e:
            logger.warning(f"ML prioritization failed: {e}. Falling back to severity-based sorting.")
            return []
    
    def _sort_by_severity(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Fallback sorting by severity if ML prioritization fails.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Sorted list (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        """
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        return sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.severity.upper() if v.severity else 'MEDIUM', 2)
        )
    
    
    def generate_suggestions(
        self,
        vulnerabilities: List[Vulnerability],
        language: str = "java",
        include_patches: bool = True
    ) -> List[Suggestion]:
        """
        Génère des suggestions pour une liste de vulnérabilités.
        (Version synchrone - utilise le tri par sévérité)
        
        Args:
            vulnerabilities: Liste des vulnérabilités
            language: Langage de programmation cible
            include_patches: Inclure les patches de code
            
        Returns:
            Liste des suggestions
        """
        # Sort by severity as fallback
        sorted_vulns = self._sort_by_severity(vulnerabilities)
        
        suggestions = []
        
        for i, vuln in enumerate(sorted_vulns):
            logger.info(f"Processing vulnerability {i+1}/{len(sorted_vulns)}: {vuln.id}")
            
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
    
    async def generate_suggestions_with_ml_priority(
        self,
        scan_id: str,
        vulnerabilities: List[Vulnerability],
        language: str = "java",
        include_patches: bool = True,
        max_suggestions: int = 10
    ) -> List[Suggestion]:
        """
        Génère des suggestions pour une liste de vulnérabilités avec priorisation ML.
        
        Cette version appelle le service ml-model pour obtenir les scores LightGBM,
        trie les vulnérabilités par priorité, et génère des suggestions Amazon Bedrock
        pour les top N vulnérabilités.
        
        Args:
            scan_id: L'ID du scan
            vulnerabilities: Liste des vulnérabilités
            language: Langage de programmation cible
            include_patches: Inclure les patches de code
            max_suggestions: Nombre maximum de suggestions à générer (par défaut 10 pour économiser les appels API)
            
        Returns:
            Liste des suggestions triées par priorité LightGBM
        """
        logger.info(f"Generating ML-prioritized suggestions for {len(vulnerabilities)} vulnerabilities")
        
        # 1. Get ML priorities
        ml_priorities = await self._prioritize_with_ml(scan_id, vulnerabilities)
        
        # 2. Create vulnerability ID to LightGBM data mapping
        priority_map = {}
        if ml_priorities:
            for prio in ml_priorities:
                priority_map[prio['vulnerability_id']] = {
                    'confidence': prio['confidence'],
                    'category': prio['lightgbm_category'],
                    'rank': prio['priority_rank']
                }
        
        # 3. Sort vulnerabilities by ML priority (or severity as fallback)
        if ml_priorities:
            # Sort by ML rank
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: priority_map.get(v.id, {}).get('rank', 999)
            )
            logger.info(f"Sorted by ML priority. Top vulnerability: {sorted_vulns[0].title if sorted_vulns else 'None'}")
        else:
            # Fallback to severity sorting
            sorted_vulns = self._sort_by_severity(vulnerabilities)
            logger.info("Using severity-based sorting (ML prioritization unavailable)")
        
        # 4. Generate suggestions for top N vulnerabilities
        suggestions = []
        vulns_to_process = sorted_vulns[:max_suggestions]
        
        logger.info(f"Generating AI suggestions for top {len(vulns_to_process)} vulnerabilities (out of {len(sorted_vulns)} total)")
        
        for i, vuln in enumerate(vulns_to_process):
            ml_data = priority_map.get(vuln.id, {})
            lightgbm_confidence = ml_data.get('confidence', 0.0)
            lightgbm_category = ml_data.get('category', 'UNKNOWN')
            
            logger.info(f"Processing {i+1}/{len(vulns_to_process)}: {vuln.id} (LightGBM: {lightgbm_confidence:.2%}, Category: {lightgbm_category})")
            
            try:
                suggestion = self.generate_suggestion(
                    vulnerability=vuln,
                    language=language,
                    include_patch=include_patches
                )
                
                # Enhance suggestion with ML data
                suggestion.lightgbm_confidence = lightgbm_confidence
                suggestion.lightgbm_category = lightgbm_category
                suggestion.priority_rank = ml_data.get('rank', i + 1)
                
                suggestions.append(suggestion)
                
            except Exception as e:
                logger.error(f"Error generating suggestion for {vuln.id}: {e}")
                
                # Créer une suggestion d'erreur
                error_suggestion = Suggestion(
                    vulnerability_id=vuln.id,
                    vulnerability_title=vuln.title,
                    enriched_recommendation=f"Erreur lors de la génération: {str(e)}",
                    confidence=0.0
                )
                error_suggestion.lightgbm_confidence = lightgbm_confidence
                error_suggestion.lightgbm_category = lightgbm_category
                error_suggestion.priority_rank = ml_data.get('rank', i + 1)
                
                suggestions.append(error_suggestion)
        
        logger.info(f"Generated {len(suggestions)} ML-prioritized suggestions")
        return suggestions


# Instance globale du générateur
suggestion_generator = SuggestionGenerator()


def get_suggestion_generator() -> SuggestionGenerator:
    """
    Retourne l'instance du générateur de suggestions.
    """
    return suggestion_generator
