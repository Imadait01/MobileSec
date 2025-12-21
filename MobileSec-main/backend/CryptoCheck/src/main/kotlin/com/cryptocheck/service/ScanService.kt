package com.cryptocheck.service

import com.cryptocheck.model.CryptoResult
import com.cryptocheck.model.CryptoSummary
import com.cryptocheck.model.ScanReport
import com.cryptocheck.model.Vulnerability
import com.cryptocheck.repository.ApkResultRepository
import com.cryptocheck.repository.CryptoResultRepository
import com.cryptocheck.scanner.CodeScanner
import org.slf4j.LoggerFactory
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.Criteria
import org.springframework.data.mongodb.core.query.Query
import org.springframework.data.mongodb.core.query.Update
import org.springframework.stereotype.Service
import java.io.IOException
import java.time.LocalDateTime

/**
 * Service de gestion des scans de code.
 * 
 * Orchestre le processus de scan et génère les rapports.
 * Intégré avec MongoDB pour lire/écrire les résultats.
 */
@Service
class ScanService(
    private val codeScanner: CodeScanner,
    private val apkResultRepository: ApkResultRepository,
    private val cryptoResultRepository: CryptoResultRepository,
    private val mongoTemplate: MongoTemplate
) {
    
    companion object {
        private val log = LoggerFactory.getLogger(ScanService::class.java)
    }
    
    private var currentReport: ScanReport? = null
    
    /**
     * Lance un scan basé sur un scan_id (lit depuis MongoDB).
     * 
     * @param scanId ID du scan dont les résultats APK sont dans MongoDB
     * @return CryptoResult contenant les vulnérabilités détectées
     */
    fun analyzeFromMongo(scanId: String): CryptoResult {
        log.info("Démarrage de l'analyse crypto pour scan_id: {}", scanId)
        
        // Update stage in scans collection
        updateScanStage(scanId, "in_progress")
        
        // Get APK results from MongoDB
        val apkResult = apkResultRepository.findByScanId(scanId)
        if (apkResult.isEmpty) {
            log.error("APK results not found for scan_id: {}", scanId)
            updateScanStage(scanId, "failed")
            throw IllegalArgumentException("APK results not found for scan_id: $scanId")
        }
        
        var decompiledPath = apkResult.get().results?.decompiledPath
            ?: throw IllegalArgumentException("Decompiled path not found in APK results")
        
        // Remap path: APK-Scanner stores /app/decompiled/xxx, we have it mounted at /app/apk-input
        if (decompiledPath.startsWith("/app/decompiled")) {
            decompiledPath = decompiledPath.replace("/app/decompiled", "/app/apk-input")
            log.info("Remapped path to: {}", decompiledPath)
        }
        
        // Perform scan
        val result = scanDirectory(decompiledPath, scanId)
        
        // Update stage
        updateScanStage(scanId, "completed")
        
        log.info("✅ Crypto analysis completed for scan_id: {} - {} vulnerabilities found", 
            scanId, result.totalVulnerabilities)
        
        return result
    }
    
    /**
     * Lance un scan sur un dossier donné.
     * 
     * @param directoryPath Chemin du dossier à scanner
     * @param scanId Optional scan ID for MongoDB storage
     * @return CryptoResult contenant toutes les vulnérabilités détectées
     * @throws IOException Si une erreur survient lors du scan
     */
    @Throws(IOException::class)
    fun scanDirectory(directoryPath: String, scanId: String? = null): CryptoResult {
        val startTime = System.currentTimeMillis()
        log.info("Démarrage du scan pour le dossier : {}", directoryPath)
        
        val vulnerabilities = codeScanner.scanDirectory(directoryPath)
        val duration = System.currentTimeMillis() - startTime
        
        // Calculate summary
        val summary = calculateSummary(vulnerabilities)
        
        val finalScanId = scanId ?: "local-${System.currentTimeMillis()}"
        
        val result = CryptoResult(
            scanId = finalScanId,
            status = "completed",
            scannedPath = directoryPath,
            totalVulnerabilities = vulnerabilities.size,
            vulnerabilities = vulnerabilities,
            summary = summary,
            scanDurationMs = duration
        )
        
        // Save to MongoDB
        saveCryptoResult(result)
        
        // Also maintain backward compatibility with ScanReport
        this.currentReport = ScanReport(
            scannedPath = directoryPath,
            scanDate = LocalDateTime.now(),
            totalVulnerabilities = vulnerabilities.size,
            vulnerabilities = vulnerabilities,
            scanDurationMs = duration
        )
        
        log.info("Scan terminé en {} ms. {} vulnérabilités détectées.", duration, vulnerabilities.size)
        
        return result
    }
    
    private fun calculateSummary(vulnerabilities: List<Vulnerability>): CryptoSummary {
        val byType = vulnerabilities.groupBy { it.vulnerability }.mapValues { it.value.size }
        
        // Map severity levels based on CWE
        var high = 0
        var medium = 0
        var low = 0
        
        vulnerabilities.forEach { vuln ->
            // Determine severity based on CWE or vulnerability description
            when {
                vuln.cwe.contains("327") -> high++ // Broken crypto
                vuln.vulnerability.contains("MD5", ignoreCase = true) -> high++
                vuln.vulnerability.contains("SHA-1", ignoreCase = true) -> medium++
                vuln.cwe.contains("330") -> medium++ // Weak random
                vuln.vulnerability.contains("ECB", ignoreCase = true) -> high++
                else -> low++
            }
        }
        
        return CryptoSummary(
            high = high,
            medium = medium,
            low = low,
            info = 0,
            byType = byType
        )
    }
    
    private fun saveCryptoResult(result: CryptoResult) {
        try {
            // Upsert based on scan_id
            val existing = cryptoResultRepository.findByScanId(result.scanId)
            if (existing.isPresent) {
                val updated = result.copy(
                    id = existing.get().id,
                    updatedAt = LocalDateTime.now()
                )
                cryptoResultRepository.save(updated)
            } else {
                cryptoResultRepository.save(result)
            }
            log.info("Crypto results saved to MongoDB for scan_id: {}", result.scanId)
        } catch (e: Exception) {
            log.error("Error saving crypto results: {}", e.message)
        }
    }
    
    private fun updateScanStage(scanId: String, status: String) {
        try {
            val query = Query(Criteria.where("scan_id").`is`(scanId))
            val update = Update()
                .set("stages.crypto_check", status)
                .set("updated_at", LocalDateTime.now())
            mongoTemplate.updateFirst(query, update, "scans")
        } catch (e: Exception) {
            log.warn("Could not update scan stage: {}", e.message)
        }
    }
    
    /**
     * Get crypto results by scan_id from MongoDB
     */
    fun getResultByScanId(scanId: String): CryptoResult? {
        return cryptoResultRepository.findByScanId(scanId).orElse(null)
    }
    
    /**
     * Get all crypto results
     */
    fun getAllResults(limit: Int = 100): List<CryptoResult> {
        return cryptoResultRepository.findAll().take(limit)
    }
    
    /**
     * Delete crypto results by scan_id
     */
    fun deleteResult(scanId: String): Boolean {
        return cryptoResultRepository.deleteByScanId(scanId) > 0
    }
    
    /**
     * Get statistics
     */
    fun getStatistics(): Map<String, Any> {
        val total = cryptoResultRepository.count()
        val withVulns = cryptoResultRepository.findAll().count { it.totalVulnerabilities > 0 }
        val totalVulns = cryptoResultRepository.findAll().sumOf { it.totalVulnerabilities }
        
        return mapOf(
            "total_scans" to total,
            "scans_with_vulnerabilities" to withVulns,
            "total_vulnerabilities" to totalVulns,
            "avg_vulnerabilities_per_scan" to if (total > 0) totalVulns.toDouble() / total else 0.0
        )
    }
    
    /**
     * Récupère le dernier rapport de scan généré.
     * 
     * @return Le dernier rapport de scan, ou null si aucun scan n'a été effectué
     */
    fun getLastReport(): ScanReport? {
        if (currentReport == null) {
            log.warn("Aucun rapport de scan disponible")
            return null
        }
        return currentReport
    }
}

