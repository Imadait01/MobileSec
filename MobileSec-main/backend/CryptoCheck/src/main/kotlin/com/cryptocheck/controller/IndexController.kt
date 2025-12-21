package com.cryptocheck.controller

import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Contrôleur pour la page d'accueil et health check.
 */
@RestController
@Tag(name = "Health", description = "Endpoints de santé")
class IndexController(
    private val mongoTemplate: MongoTemplate
) {
    
    /**
     * Endpoint racine pour afficher les informations de l'API.
     */
    @GetMapping("/")
    @Operation(summary = "Page d'accueil de l'API")
    fun index(): Map<String, Any> {
        val mongoConnected = try {
            mongoTemplate.db.runCommand(org.bson.Document("ping", 1))
            true
        } catch (e: Exception) {
            false
        }
        
        return mapOf(
            "service" to "CryptoCheck",
            "version" to "2.0.0",
            "description" to "Scanner SAST pour vulnérabilités cryptographiques",
            "swagger" to "/swagger-ui.html",
            "mongodb_connected" to mongoConnected,
            "endpoints" to mapOf(
                "POST /api/analyze" to "Analyse depuis MongoDB (appelé par APK-Scanner)",
                "POST /api/scan" to "Scanner un dossier directement",
                "GET /api/results/{scanId}" to "Récupérer les résultats par ID",
                "GET /api/results" to "Lister tous les résultats",
                "DELETE /api/results/{scanId}" to "Supprimer les résultats",
                "GET /api/stats" to "Statistiques",
                "GET /api/report" to "Dernier rapport (legacy)"
            )
        )
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    @Operation(summary = "Vérification de santé du service")
    fun health(): Map<String, Any> {
        val mongoConnected = try {
            mongoTemplate.db.runCommand(org.bson.Document("ping", 1))
            true
        } catch (e: Exception) {
            false
        }
        
        return mapOf(
            "status" to "healthy",
            "mongodb" to mongoConnected,
            "timestamp" to java.time.LocalDateTime.now().toString(),
            "service" to "CryptoCheck"
        )
    }

    /**
     * Health check endpoint alias
     */
    @GetMapping("/api/health")
    @Operation(summary = "Vérification de santé du service (Alias)")
    fun apiHealth(): Map<String, Any> {
        return health()
    }
}

