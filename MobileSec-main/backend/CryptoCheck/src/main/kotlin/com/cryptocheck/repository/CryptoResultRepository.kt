package com.cryptocheck.repository

import com.cryptocheck.model.CryptoResult
import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.stereotype.Repository
import java.util.Optional

/**
 * Repository MongoDB pour les résultats crypto
 */
@Repository
interface CryptoResultRepository : MongoRepository<CryptoResult, String> {
    
    fun findByScanId(scanId: String): Optional<CryptoResult>
    
    fun existsByScanId(scanId: String): Boolean
    
    fun deleteByScanId(scanId: String): Long
    
    fun countByStatus(status: String): Long
}
