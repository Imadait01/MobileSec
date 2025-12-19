package com.cryptocheck.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.data.mongodb.core.mapping.Field
import java.time.LocalDateTime

/**
 * Modèle pour les résultats APK stockés dans MongoDB (collection: apk_results)
 * Sert comme INPUT pour CryptoCheck
 */
@Document(collection = "apk_results")
data class ApkResult(
    @Id
    val id: String? = null,
    
    @Field("scan_id")
    val scanId: String,
    
    val status: String = "pending",
    
    @Field("created_at")
    val createdAt: LocalDateTime = LocalDateTime.now(),
    
    val results: ApkResultDetails? = null
)

data class ApkResultDetails(
    @Field("app_name")
    val appName: String? = null,
    
    @Field("package_name")
    val packageName: String? = null,
    
    @Field("decompiled_path")
    val decompiledPath: String? = null,
    
    @Field("apk_path")
    val apkPath: String? = null,
    
    val manifest: Map<String, Any>? = null
)
