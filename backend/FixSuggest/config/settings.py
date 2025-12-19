"""
FixSuggest - Configuration Settings
====================================
Charge les variables d'environnement AWS et autres configurations.
Utilise Pydantic BaseSettings pour la validation automatique.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os


class Settings(BaseSettings):
    """
    Configuration principale du service FixSuggest.
    Les valeurs sont chargées depuis les variables d'environnement.
    """
    
    # ==================== Application ====================
    app_name: str = Field(default="FixSuggest", description="Nom de l'application")
    app_version: str = Field(default="1.0.0", description="Version de l'application")
    debug: bool = Field(default=False, description="Mode debug")
    host: str = Field(default="0.0.0.0", description="Host du serveur")
    port: int = Field(default=8000, description="Port du serveur")
    
    # ==================== OpenRouter API ====================
    openrouter_api_key: Optional[str] = Field(
        default=None, 
        description="OpenRouter API Key"
    )
    openrouter_model: str = Field(
        default="amazon/nova-lite-v1",
        description="Modèle OpenRouter (Amazon Nova 2 Lite)"
    )
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1",
        description="URL de base OpenRouter"
    )
    
    # Paramètres du modèle
    llm_max_tokens: int = Field(default=2048, description="Nombre max de tokens")
    llm_temperature: float = Field(default=0.3, description="Température du modèle")
    llm_top_p: float = Field(default=0.9, description="Top P sampling")

    # ==================== Kafka ====================
    kafka_brokers: str = Field(
        default="kafka:9092",
        description="Brokers Kafka (séparés par virgule)"
    )
    
    # ==================== MongoDB (optionnel) ====================
    mongodb_uri: Optional[str] = Field(
        default="mongodb://admin:securityplatform2024@mongodb:27017/security_platform?authSource=admin",
        description="URI de connexion MongoDB"
    )
    mongodb_database: str = Field(
        default="security_platform",
        description="Nom de la base de données"
    )
    
    # ==================== Règles MASVS ====================
    rules_path: str = Field(
        default="rules/masvs",
        description="Chemin vers les fichiers YAML des règles MASVS"
    )
    
    # ==================== Logging ====================
    log_level: str = Field(default="INFO", description="Niveau de log")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Format des logs"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Instance globale des settings
settings = Settings()


def get_settings() -> Settings:
    """
    Retourne l'instance des settings.
    Utilisé pour l'injection de dépendances FastAPI.
    """
    return settings
