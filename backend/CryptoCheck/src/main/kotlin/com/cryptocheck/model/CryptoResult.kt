package com.cryptocheck.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.data.mongodb.core.mapping.Field
import java.time.LocalDateTime

/**
 * Modèle pour les résultats crypto stockés dans MongoDB (collection: crypto_results)
 * Sert comme OUTPUT de CryptoCheck
 */
@Document(collection = "crypto_results")
data class CryptoResult(
    @Id
    val id: String? = null,
    
    @Indexed(unique = true)
    @Field("scan_id")
    val scanId: String,
    
    val status: String = "completed",
    
    @Field("created_at")
    val createdAt: LocalDateTime = LocalDateTime.now(),
    
    @Field("updated_at")
    val updatedAt: LocalDateTime = LocalDateTime.now(),
    
    @Field("scanned_path")
    val scannedPath: String? = null,
    
    @Field("total_vulnerabilities")
    val totalVulnerabilities: Int = 0,
    
    val vulnerabilities: List<Vulnerability> = emptyList(),
    
    val summary: CryptoSummary = CryptoSummary(),
    
    @Field("scan_duration_ms")
    val scanDurationMs: Long = 0
)

data class CryptoSummary(
    val high: Int = 0,
    val medium: Int = 0,
    val low: Int = 0,
    val info: Int = 0,
    
    @Field("by_type")
    val byType: Map<String, Int> = emptyMap()
)
