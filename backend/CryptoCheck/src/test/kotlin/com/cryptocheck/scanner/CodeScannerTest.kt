package com.cryptocheck.scanner

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.*

/**
 * Tests unitaires pour le scanner de code.
 */
class CodeScannerTest {
    
    private lateinit var codeScanner: CodeScanner
    
    @TempDir
    lateinit var tempDir: Path
    
    @BeforeEach
    fun setUp() {
        codeScanner = CodeScanner()
    }
    
    @Test
    fun testAESECBDetection() {
        // Créer un fichier Java avec AES/ECB
        val testFile = tempDir.resolve("TestAES.java").toFile()
        testFile.writeText("""
            import javax.crypto.Cipher;
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        """.trimIndent())
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(1, vulnerabilities.size)
        val vuln = vulnerabilities[0]
        assertEquals("AES/ECB usage", vuln.vulnerability)
        assertEquals("CWE-327", vuln.cwe)
        assertNotNull(vuln.recommendation)
    }
    
    @Test
    fun testAESNoPaddingDetection() {
        // Créer un fichier Java avec AES sans padding
        val testFile = tempDir.resolve("TestNoPadding.java").toFile()
        testFile.writeText("Cipher.getInstance(\"AES/CBC/NoPadding\");")
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(1, vulnerabilities.size)
        val vuln = vulnerabilities[0]
        assertEquals("AES without proper padding", vuln.vulnerability)
        assertEquals("CWE-327", vuln.cwe)
    }
    
    @Test
    fun testWeakRandomDetection() {
        // Créer un fichier Java avec Random
        val testFile = tempDir.resolve("TestRandom.java").toFile()
        testFile.writeText("""
            import java.util.Random;
            Random random = new Random();
        """.trimIndent())
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertTrue(vulnerabilities.size >= 1)
        val found = vulnerabilities.any { it.vulnerability.contains("Weak random generator") }
        assertTrue(found, "Devrait détecter l'utilisation de Random")
    }
    
    @Test
    fun testMD5Detection() {
        // Créer un fichier Java avec MD5
        val testFile = tempDir.resolve("TestMD5.java").toFile()
        testFile.writeText("MessageDigest md = MessageDigest.getInstance(\"MD5\");")
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(1, vulnerabilities.size)
        val vuln = vulnerabilities[0]
        assertEquals("MD5 hash usage (deprecated and vulnerable)", vuln.vulnerability)
        assertEquals("CWE-327", vuln.cwe)
    }
    
    @Test
    fun testSHA1Detection() {
        // Créer un fichier Java avec SHA-1
        val testFile = tempDir.resolve("TestSHA1.java").toFile()
        testFile.writeText("MessageDigest md = MessageDigest.getInstance(\"SHA-1\");")
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(1, vulnerabilities.size)
        val vuln = vulnerabilities[0]
        assertEquals("SHA-1 hash usage (deprecated)", vuln.vulnerability)
        assertEquals("CWE-327", vuln.cwe)
    }
    
    @Test
    fun testPythonMD5Detection() {
        // Créer un fichier Python avec MD5
        val testFile = tempDir.resolve("test_md5.py").toFile()
        testFile.writeText("""
            import hashlib
            hashlib.md5(b'test').hexdigest()
        """.trimIndent())
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(1, vulnerabilities.size)
        val vuln = vulnerabilities[0]
        assertEquals("MD5 hash usage (deprecated and vulnerable)", vuln.vulnerability)
    }
    
    @Test
    fun testMultipleVulnerabilities() {
        // Créer un fichier avec plusieurs vulnérabilités
        val testFile = tempDir.resolve("MultipleVulns.java").toFile()
        testFile.writeText("""
            import java.util.Random;
            import java.security.MessageDigest;
            Random r = new Random();
            MessageDigest.getInstance("MD5");
            Cipher.getInstance("AES/ECB/PKCS5Padding");
        """.trimIndent())
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertTrue(vulnerabilities.size >= 3, "Devrait détecter au moins 3 vulnérabilités")
    }
    
    @Test
    fun testInvalidDirectory() {
        assertThrows(IllegalArgumentException::class.java) {
            codeScanner.scanDirectory("/chemin/inexistant/12345")
        }
    }
    
    @Test
    fun testUnsupportedFileType() {
        // Créer un fichier non supporté
        val testFile = tempDir.resolve("test.txt").toFile()
        testFile.writeText("MessageDigest.getInstance(\"MD5\");")
        
        val vulnerabilities = codeScanner.scanDirectory(tempDir.toString())
        
        assertEquals(0, vulnerabilities.size, "Ne devrait pas scanner les fichiers .txt")
    }
}

