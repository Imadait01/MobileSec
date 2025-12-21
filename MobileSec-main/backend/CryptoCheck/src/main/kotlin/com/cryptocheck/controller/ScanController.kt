package com.cryptocheck.controller

import com.cryptocheck.model.CryptoResult
import com.cryptocheck.model.ScanReport
import com.cryptocheck.model.ScanRequest
import com.cryptocheck.service.ScanService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

/**
 * Contrôleur REST pour l'API de scan de code cryptographique.
 * 
 * Lit depuis MongoDB (apk_results), écrit dans MongoDB (crypto_results)
 */
@RestController
@RequestMapping("/api")
@Tag(name = "Crypto Scan", description = "API pour l'analyse de vulnérabilités cryptographiques")
class ScanController(
    private val scanService: ScanService
) {
    
    companion object {
        private val log = LoggerFactory.getLogger(ScanController::class.java)
    }
    
    /**
     * Endpoint pour analyser le code depuis MongoDB (appelé par APK-Scanner)
     */
    @PostMapping("/analyze")
    @Operation(
        summary = "Analyser le code depuis MongoDB",
        description = "Lit le chemin de code décompilé depuis apk_results et analyse les vulnérabilités cryptographiques"
    )
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "Analyse terminée"),
        ApiResponse(responseCode = "400", description = "Paramètres invalides"),
        ApiResponse(responseCode = "404", description = "Résultats APK non trouvés"),
        ApiResponse(responseCode = "500", description = "Erreur serveur")
    )
    fun analyzeFromMongo(
        @RequestBody request: AnalyzeRequest
    ): ResponseEntity<*> {
        return try {
            log.info("Requête d'analyse reçue pour scan_id: {}", request.scanId)
            val result = scanService.analyzeFromMongo(request.scanId)
            ResponseEntity.ok(mapOf(
                "status" to "success",
                "scan_id" to result.scanId,
                "vulnerabilities_found" to result.totalVulnerabilities,
                "summary" to result.summary
            ))
        } catch (e: IllegalArgumentException) {
            log.error("Erreur de validation: {}", e.message)
            ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse("Not Found", e.message ?: "APK results not found"))
        } catch (e: Exception) {
            log.error("Erreur lors de l'analyse: {}", e.message, e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse("Erreur serveur", e.message ?: "Erreur inconnue"))
        }
    }
    
    /**
     * Endpoint pour lancer un scan direct sur un dossier.
     */
    @PostMapping("/scan")
    @Operation(
        summary = "Scanner un dossier",
        description = "Lance un scan direct sur un dossier de code"
    )
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "Scan terminé"),
        ApiResponse(responseCode = "400", description = "Chemin invalide"),
        ApiResponse(responseCode = "500", description = "Erreur serveur")
    )
    fun scanDirectory(@Valid @RequestBody request: ScanRequest): ResponseEntity<*> {
        return try {
            log.info("Requête de scan reçue pour : {}", request.directoryPath)
            val result = scanService.scanDirectory(request.directoryPath)
            ResponseEntity.ok(result)
        } catch (e: IllegalArgumentException) {
            log.error("Erreur de validation : {}", e.message)
            ResponseEntity.badRequest()
                .body(ErrorResponse("Erreur de validation", e.message ?: "Erreur inconnue"))
        } catch (e: java.io.IOException) {
            log.error("Erreur lors du scan : {}", e.message)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse("Erreur lors du scan", e.message ?: "Erreur inconnue"))
        } catch (e: Exception) {
            log.error("Erreur inattendue : {}", e.message, e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse("Erreur inattendue", e.message ?: "Erreur inconnue"))
        }
    }
    
    /**
     * Récupérer les résultats par scan_id
     */
    @GetMapping("/results/{scanId}")
    @Operation(summary = "Récupérer les résultats par scan_id")
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "Résultats trouvés"),
        ApiResponse(responseCode = "404", description = "Résultats non trouvés")
    )
    fun getResults(
        @Parameter(description = "ID du scan") @PathVariable scanId: String
    ): ResponseEntity<*> {
        val result = scanService.getResultByScanId(scanId)
        return if (result == null) {
            ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse("Not Found", "No results found for scan_id: $scanId"))
        } else {
            ResponseEntity.ok(result)
        }
    }
    
    /**
     * Lister tous les résultats
     */
    @GetMapping("/results")
    @Operation(summary = "Lister tous les résultats")
    fun listResults(
        @Parameter(description = "Limite") @RequestParam(defaultValue = "100") limit: Int
    ): ResponseEntity<*> {
        val results = scanService.getAllResults(limit)
        return ResponseEntity.ok(mapOf(
            "count" to results.size,
            "results" to results
        ))
    }
    
    /**
     * Supprimer les résultats par scan_id
     */
    @DeleteMapping("/results/{scanId}")
    @Operation(summary = "Supprimer les résultats par scan_id")
    fun deleteResults(
        @Parameter(description = "ID du scan") @PathVariable scanId: String
    ): ResponseEntity<*> {
        val deleted = scanService.deleteResult(scanId)
        return if (deleted) {
            ResponseEntity.ok(mapOf("message" to "Results deleted", "scan_id" to scanId))
        } else {
            ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse("Not Found", "No results found for scan_id: $scanId"))
        }
    }
    
    /**
     * Récupérer les statistiques
     */
    @GetMapping("/stats")
    @Operation(summary = "Récupérer les statistiques")
    fun getStats(): ResponseEntity<*> {
        val stats = scanService.getStatistics()
        return ResponseEntity.ok(stats)
    }
    
    /**
     * Endpoint pour récupérer le dernier rapport de scan (legacy).
     */
    @GetMapping("/report")
    @Operation(
        summary = "Récupérer le dernier rapport",
        description = "Récupère le dernier rapport de scan généré (legacy)"
    )
    fun getReport(): ResponseEntity<*> {
        val report = scanService.getLastReport()
        return if (report == null) {
            ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse(
                    "Aucun rapport disponible",
                    "Aucun scan n'a été effectué. Utilisez POST /api/scan pour lancer un scan."
                ))
        } else {
            ResponseEntity.ok(report)
        }
    }
    
    /**
     * Classe de requête pour l'analyse depuis MongoDB
     */
    data class AnalyzeRequest(
        val scanId: String
    )
    
    /**
     * Classe de données pour les réponses d'erreur.
     */
    data class ErrorResponse(
        val error: String,
        val message: String
    )
}

