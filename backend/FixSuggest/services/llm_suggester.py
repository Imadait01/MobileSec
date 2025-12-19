"""
FixSuggest - LLM Suggester (Amazon Nova 2 Lite via OpenRouter)
==============================================================
Client pour OpenRouter API utilisant le modèle Amazon Nova 2 Lite.
Génère des recommandations enrichies et des patches de code.
"""

import json
import logging
import httpx
from typing import Optional, Dict, Any

from config import settings
from models import Vulnerability, MASVSRule

logger = logging.getLogger(__name__)


class NovaClient:
    """
    Client pour Amazon Nova 2 Lite via OpenRouter API.
    Génère des suggestions de correction enrichies par IA.
    """
    
    def __init__(self):
        """
        Initialise le client OpenRouter.
        """
        self.api_key = settings.openrouter_api_key
        self.model = settings.openrouter_model
        self.base_url = settings.openrouter_base_url
        self.max_tokens = settings.llm_max_tokens
        self.temperature = settings.llm_temperature
        self.top_p = settings.llm_top_p
        
        self._is_configured = bool(self.api_key)
        
        if self._is_configured:
            logger.info(f"OpenRouter client initialized")
            logger.info(f"Using model: {self.model}")
        else:
            logger.warning("OpenRouter API key not found. LLM features will be disabled.")
    
    @property
    def is_configured(self) -> bool:
        """Vérifie si le client est configuré."""
        return self._is_configured
    
    def _build_prompt(
        self, 
        vulnerability: Vulnerability, 
        masvs_rule: Optional[MASVSRule],
        language: str = "java"
    ) -> str:
        """
        Construit le prompt pour le LLM.
        
        Args:
            vulnerability: La vulnérabilité à analyser
            masvs_rule: La règle MASVS associée (optionnelle)
            language: Langage de programmation cible
            
        Returns:
            Le prompt formaté
        """
        # Informations sur la vulnérabilité
        vuln_info = f"""
## Vulnérabilité Détectée
- **ID**: {vulnerability.id}
- **Titre**: {vulnerability.title or 'N/A'}
- **Description**: {vulnerability.description or 'N/A'}
- **Sévérité**: {vulnerability.severity or 'N/A'}
- **Fichier**: {vulnerability.file or 'N/A'}
- **Ligne**: {vulnerability.line or 'N/A'}
- **CWE**: {vulnerability.cwe or 'N/A'}
"""
        
        if vulnerability.code_snippet:
            vuln_info += f"""
- **Code vulnérable**:
```{language}
{vulnerability.code_snippet}
```
"""
        
        # Informations MASVS si disponibles
        masvs_info = ""
        if masvs_rule:
            masvs_info = f"""
## Règle MASVS Associée
- **ID**: {masvs_rule.rule_id}
- **Titre**: {masvs_rule.title}
- **Description**: {masvs_rule.description or 'N/A'}
- **Recommandation de base**: {masvs_rule.recommendation}
"""
            if masvs_rule.references:
                masvs_info += f"- **Références**: {', '.join(masvs_rule.references)}\n"
        
        # Prompt complet
        prompt = f"""Tu es un expert en sécurité des applications mobiles Android.
Analyse la vulnérabilité suivante et fournis une recommandation de correction détaillée.

{vuln_info}
{masvs_info}

## Ta Mission
1. **Analyse**: Explique brièvement pourquoi cette vulnérabilité est dangereuse.
2. **Recommandation**: Fournis une recommandation détaillée et actionnable pour corriger cette vulnérabilité.
3. **Patch de Code**: Génère un exemple de code corrigé en {language}.

## Format de Réponse (JSON)
Réponds UNIQUEMENT avec un JSON valide dans ce format exact:
{{
    "analysis": "Explication courte du risque",
    "recommendation": "Recommandation détaillée pour la correction",
    "patch_code": "Code corrigé complet",
    "additional_tips": ["Conseil 1", "Conseil 2"]
}}

Réponds maintenant:"""

        return prompt
    
    async def generate_suggestion_async(
        self,
        vulnerability: Vulnerability,
        masvs_rule: Optional[MASVSRule] = None,
        language: str = "java"
    ) -> Dict[str, Any]:
        """
        Génère une suggestion de correction via Amazon Nova 2 Lite (async).
        
        Args:
            vulnerability: La vulnérabilité à analyser
            masvs_rule: La règle MASVS associée (optionnelle)
            language: Langage de programmation cible
            
        Returns:
            Dictionnaire contenant la suggestion générée
        """
        # Si le client n'est pas configuré, retourner une suggestion basique
        if not self._is_configured:
            return self._generate_fallback_suggestion(vulnerability, masvs_rule, language)
        
        try:
            # Construire le prompt
            prompt = self._build_prompt(vulnerability, masvs_rule, language)
            
            # Préparer la requête pour OpenRouter
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "FixSuggest Security Platform"
            }
            
            request_body = {
                "model": self.model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p
            }
            
            logger.debug(f"Calling OpenRouter model: {self.model}")
            
            # Appeler OpenRouter
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=request_body
                )
                response.raise_for_status()
                data = response.json()
            
            # Extraire la réponse
            choices = data.get("choices", [])
            if choices:
                response_text = choices[0].get("message", {}).get("content", "")
                
                # Parser le JSON de la réponse
                try:
                    # Nettoyer la réponse (enlever markdown si présent)
                    clean_text = response_text.strip()
                    if clean_text.startswith("```json"):
                        clean_text = clean_text[7:]
                    if clean_text.startswith("```"):
                        clean_text = clean_text[3:]
                    if clean_text.endswith("```"):
                        clean_text = clean_text[:-3]
                    
                    suggestion_data = json.loads(clean_text.strip())
                    
                    return {
                        "success": True,
                        "analysis": suggestion_data.get("analysis", ""),
                        "recommendation": suggestion_data.get("recommendation", ""),
                        "patch_code": suggestion_data.get("patch_code", ""),
                        "additional_tips": suggestion_data.get("additional_tips", []),
                        "model_used": self.model
                    }
                    
                except json.JSONDecodeError:
                    # Si le parsing JSON échoue, retourner le texte brut
                    logger.warning("Failed to parse LLM response as JSON, using raw text")
                    return {
                        "success": True,
                        "analysis": "",
                        "recommendation": response_text,
                        "patch_code": masvs_rule.patches.get(language, "") if masvs_rule else "",
                        "additional_tips": [],
                        "model_used": self.model
                    }
            
            logger.warning("Empty response from OpenRouter")
            return self._generate_fallback_suggestion(vulnerability, masvs_rule, language)
            
        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter API error: {e.response.status_code} - {e.response.text}")
            return self._generate_fallback_suggestion(vulnerability, masvs_rule, language)
            
        except Exception as e:
            logger.error(f"Error generating suggestion: {e}")
            return self._generate_fallback_suggestion(vulnerability, masvs_rule, language)
    
    def generate_suggestion(
        self,
        vulnerability: Vulnerability,
        masvs_rule: Optional[MASVSRule] = None,
        language: str = "java"
    ) -> Dict[str, Any]:
        """
        Génère une suggestion de correction (sync wrapper).
        Pour la compatibilité, utilise la version async via asyncio.
        """
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Si on est déjà dans une boucle async, créer une tâche
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self.generate_suggestion_async(vulnerability, masvs_rule, language)
                    )
                    return future.result()
            else:
                return loop.run_until_complete(
                    self.generate_suggestion_async(vulnerability, masvs_rule, language)
                )
        except RuntimeError:
            return asyncio.run(
                self.generate_suggestion_async(vulnerability, masvs_rule, language)
            )
    
    def _generate_fallback_suggestion(
        self,
        vulnerability: Vulnerability,
        masvs_rule: Optional[MASVSRule],
        language: str
    ) -> Dict[str, Any]:
        """
        Génère une suggestion de base sans LLM.
        
        Args:
            vulnerability: La vulnérabilité
            masvs_rule: La règle MASVS
            language: Le langage cible
            
        Returns:
            Suggestion basique
        """
        if masvs_rule:
            recommendation = masvs_rule.recommendation
            patch_code = masvs_rule.patches.get(language, "")
            
            if not patch_code and masvs_rule.patches:
                # Prendre le premier patch disponible
                patch_code = next(iter(masvs_rule.patches.values()), "")
        else:
            recommendation = f"Corriger la vulnérabilité '{vulnerability.title or vulnerability.id}' selon les bonnes pratiques de sécurité."
            patch_code = ""
        
        return {
            "success": True,
            "analysis": f"Vulnérabilité de type {vulnerability.title or vulnerability.id} détectée.",
            "recommendation": recommendation,
            "patch_code": patch_code,
            "additional_tips": [
                "Consulter la documentation OWASP MASVS",
                "Effectuer une revue de code approfondie"
            ],
            "model_used": "fallback (no LLM)"
        }
    
    async def generate_natural_suggestion_async(
        self,
        vuln_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Génère une suggestion en PHRASES NATURELLES et LISIBLES.
        Conçu pour être affiché dans une interface utilisateur.
        
        Args:
            vuln_data: Dictionnaire avec les infos de la vulnérabilité
            
        Returns:
            Suggestion avec des phrases naturelles
        """
        if not self._is_configured:
            return self._generate_natural_fallback(vuln_data)
        
        try:
            # Prompt optimisé pour des phrases naturelles
            prompt = f"""Tu es un expert en sécurité mobile qui explique les problèmes de sécurité de façon claire et accessible.

## Vulnérabilité à expliquer:
- Type: {vuln_data.get('title', 'Problème de sécurité')}
- Description: {vuln_data.get('description', '')}
- Sévérité: {vuln_data.get('severity', 'MEDIUM')}
- Fichier: {vuln_data.get('file', 'Non spécifié')}
- Outil: {vuln_data.get('tool', 'Scanner')}

## Ta mission:
Génère une explication et une recommandation en PHRASES NATURELLES, comme si tu parlais à un développeur.
Les phrases doivent être:
- Claires et compréhensibles
- Directes et actionnables
- Sans jargon technique excessif

## Format de réponse (JSON uniquement):
{{
    "titre_simple": "Un titre court et clair en français",
    "explication": "2-3 phrases expliquant le problème et ses risques",
    "solution": "2-3 phrases expliquant comment corriger le problème",
    "priorite": "Une phrase indiquant l'urgence de la correction",
    "exemple_correction": "Un court exemple de code corrigé si applicable, sinon null"
}}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après:"""

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "FixSuggest Security Platform"
            }
            
            request_body = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.max_tokens,
                "temperature": 0.4  # Un peu plus créatif pour les phrases naturelles
            }
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=request_body
                )
                response.raise_for_status()
                data = response.json()
            
            choices = data.get("choices", [])
            if choices:
                response_text = choices[0].get("message", {}).get("content", "")
                
                # Parser le JSON
                try:
                    clean_text = response_text.strip()
                    if clean_text.startswith("```json"):
                        clean_text = clean_text[7:]
                    if clean_text.startswith("```"):
                        clean_text = clean_text[3:]
                    if clean_text.endswith("```"):
                        clean_text = clean_text[:-3]
                    
                    suggestion_data = json.loads(clean_text.strip())
                    
                    return {
                        "vulnerability_id": vuln_data.get("id"),
                        "vulnerability_title": vuln_data.get("title"),
                        "severity": vuln_data.get("severity"),
                        "file": vuln_data.get("file"),
                        "tool": vuln_data.get("tool"),
                        "titre_simple": suggestion_data.get("titre_simple", ""),
                        "explication": suggestion_data.get("explication", ""),
                        "solution": suggestion_data.get("solution", ""),
                        "priorite": suggestion_data.get("priorite", ""),
                        "exemple_correction": suggestion_data.get("exemple_correction"),
                        "model_used": self.model,
                        "generated": True
                    }
                    
                except json.JSONDecodeError:
                    logger.warning("Failed to parse natural suggestion JSON")
                    return self._generate_natural_fallback(vuln_data)
            
            return self._generate_natural_fallback(vuln_data)
            
        except Exception as e:
            logger.error(f"Error generating natural suggestion: {e}")
            return self._generate_natural_fallback(vuln_data)
    
    def _generate_natural_fallback(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère une suggestion naturelle de base sans LLM.
        """
        title = vuln_data.get("title", "Problème de sécurité")
        severity = vuln_data.get("severity", "MEDIUM")
        tool = vuln_data.get("tool", "Scanner")
        
        # Générer des phrases basiques mais naturelles
        if "MD5" in title or "SHA1" in title or "crypto" in title.lower():
            explication = f"Cette vulnérabilité concerne l'utilisation d'un algorithme de hachage obsolète. Ces algorithmes sont considérés comme cryptographiquement faibles et peuvent être exploités par des attaquants."
            solution = "Remplacez l'algorithme actuel par SHA-256 ou SHA-3 qui sont considérés comme sécurisés. Mettez à jour toutes les instances dans votre code."
        elif "secret" in title.lower() or "api" in title.lower() or "key" in title.lower():
            explication = f"Un secret ou une clé d'API a été détecté en dur dans le code source. Cela expose vos credentials à toute personne ayant accès au code."
            solution = "Supprimez immédiatement ce secret du code. Utilisez des variables d'environnement ou un gestionnaire de secrets comme Android Keystore."
        elif "http" in title.lower() or "ssl" in title.lower() or "tls" in title.lower():
            explication = f"Une communication réseau non sécurisée a été détectée. Les données transmises peuvent être interceptées par des attaquants."
            solution = "Utilisez HTTPS pour toutes les communications. Activez le certificate pinning pour une sécurité renforcée."
        else:
            explication = f"Une vulnérabilité de type '{title}' a été détectée par {tool}. Ce type de problème peut compromettre la sécurité de votre application."
            solution = "Consultez la documentation OWASP MASVS pour les bonnes pratiques de correction. Effectuez une revue de code approfondie."
        
        priorite_map = {
            "CRITICAL": "🔴 Correction URGENTE requise - Cette vulnérabilité est critique.",
            "HIGH": "🟠 Correction prioritaire recommandée - Risque de sécurité élevé.",
            "MEDIUM": "🟡 Correction à planifier - Risque modéré mais à ne pas ignorer.",
            "LOW": "🟢 Correction à considérer - Risque faible mais améliore la sécurité."
        }
        
        return {
            "vulnerability_id": vuln_data.get("id"),
            "vulnerability_title": title,
            "severity": severity,
            "file": vuln_data.get("file"),
            "tool": tool,
            "titre_simple": title,
            "explication": explication,
            "solution": solution,
            "priorite": priorite_map.get(severity, priorite_map["MEDIUM"]),
            "exemple_correction": None,
            "model_used": "fallback",
            "generated": True
        }


# Instance globale du client Nova
nova_client = NovaClient()


def get_nova_client() -> NovaClient:
    """
    Retourne l'instance du client Nova.
    """
    return nova_client
