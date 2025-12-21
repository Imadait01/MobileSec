package com.cryptocheck.service

import com.cryptocheck.scanner.CodeScanner
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.*

/**
 * Tests unitaires pour le service de scan.
 */
class ScanServiceTest {
    
    private lateinit var scanService: ScanService
    private lateinit var codeScanner: CodeScanner
    
    @TempDir
    lateinit var tempDir: Path
    
    @BeforeEach
    fun setUp() {
        codeScanner = CodeScanner()
        scanService = ScanService(codeScanner)
    }
    
    @Test
    fun testScanDirectory() {
        // Créer un fichier de test avec une vulnérabilité
        val testFile = tempDir.resolve("Test.java").toFile()
        testFile.writeText("MessageDigest.getInstance(\"MD5\");")
        
        val report = scanService.scanDirectory(tempDir.toString())
        
        assertNotNull(report)
        assertEquals(tempDir.toString(), report.scannedPath)
        assertEquals(1, report.totalVulnerabilities)
        assertNotNull(report.scanDate)
        assertNotNull(report.scanDurationMs)
        assertTrue(report.scanDurationMs >= 0)
    }
    
    @Test
    fun testGetLastReport() {
        // Aucun scan effectué
        assertNull(scanService.getLastReport())
        
        // Effectuer un scan
        val testFile = tempDir.resolve("Test.java").toFile()
        testFile.writeText("MessageDigest.getInstance(\"MD5\");")
        
        scanService.scanDirectory(tempDir.toString())
        
        val report = scanService.getLastReport()
        assertNotNull(report)
        assertEquals(1, report!!.totalVulnerabilities)
    }
    
    @Test
    fun testScanWithNoVulnerabilities() {
        // Créer un fichier sans vulnérabilités
        val testFile = tempDir.resolve("Safe.java").toFile()
        testFile.writeText("""
            import java.security.SecureRandom;
            SecureRandom random = new SecureRandom();
        """.trimIndent())
        
        val report = scanService.scanDirectory(tempDir.toString())
        
        assertNotNull(report)
        assertEquals(0, report.totalVulnerabilities)
    }
}

