"""
Models package initialization
"""
from .vulnerability import (
    Vulnerability,
    SuggestRequest,
    SuggestResponse,
    Suggestion,
    MASVSRule,
    HealthResponse,
    ErrorResponse,
    Severity,
    Category
)

__all__ = [
    "Vulnerability",
    "SuggestRequest", 
    "SuggestResponse",
    "Suggestion",
    "MASVSRule",
    "HealthResponse",
    "ErrorResponse",
    "Severity",
    "Category"
]
