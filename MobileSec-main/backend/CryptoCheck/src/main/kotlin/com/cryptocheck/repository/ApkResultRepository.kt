package com.cryptocheck.repository

import com.cryptocheck.model.ApkResult
import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.stereotype.Repository
import java.util.Optional

/**
 * Repository MongoDB pour lire les résultats APK (input)
 */
@Repository
interface ApkResultRepository : MongoRepository<ApkResult, String> {
    
    fun findByScanId(scanId: String): Optional<ApkResult>
}
