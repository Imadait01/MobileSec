package com.cryptocheck.scanner

import com.cryptocheck.model.Vulnerability
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths
import java.util.regex.Pattern

/**
 * Scanner SAST pour détecter les vulnérabilités cryptographiques dans le code source.
 * 
 * Supporte plusieurs langages de programmation :
 * - Java, Kotlin
 * - Python
 * - C#
 * - Smali (bytecode Android décompilé)
 * 
 * Détecte les vulnérabilités suivantes :
 * - AES en mode ECB
 * - Absence de padding dans AES
 * - Générateurs aléatoires faibles
 * - Hachages obsolètes (MD5, SHA-1)
 */
@Component
class CodeScanner {
    
    companion object {
        private val log = LoggerFactory.getLogger(CodeScanner::class.java)
        
        // Extensions de fichiers supportées (incluant .smali pour Android)
        private val SUPPORTED_EXTENSIONS = arrayOf(
            ".java", ".kt", ".py", ".cs", ".js", ".ts", ".smali"
        )
        
        // ============================================
        // Patterns pour code source (Java, Kotlin, etc.)
        // ============================================
        
        // AES/ECB - détecte "AES/ECB" ou "AES" sans mode spécifié
        private val AES_ECB_PATTERN = Pattern.compile(
            "(?i)(AES/ECB|Cipher\\.getInstance\\s*\\(\\s*[\"']AES[\"']\\s*\\))",
            Pattern.MULTILINE
        )
        
        // AES sans padding - détecte "AES" avec "NoPadding"
        private val AES_NO_PADDING_PATTERN = Pattern.compile(
            "(?i)(AES/[^/]+/NoPadding)",
            Pattern.MULTILINE
        )
        
        // Générateur aléatoire faible - détecte "new Random()" ou "Random()"
        private val WEAK_RANDOM_PATTERN = Pattern.compile(
            "(?i)(new\\s+Random\\s*\\(|Random\\s*\\(|import\\s+java\\.util\\.Random)",
            Pattern.MULTILINE
        )
        
        // MD5 usage
        private val MD5_PATTERN = Pattern.compile(
            "(?i)(MessageDigest\\.getInstance\\s*\\(\\s*[\"']MD5[\"']|md5|hashlib\\.md5|MD5\\.create|MD5CryptoServiceProvider)",
            Pattern.MULTILINE
        )
        
        // SHA-1 usage
        private val SHA1_PATTERN = Pattern.compile(
            "(?i)(MessageDigest\\.getInstance\\s*\\(\\s*[\"']SHA-?1[\"']|sha1|hashlib\\.sha1|SHA1\\.create|SHA1CryptoServiceProvider)",
            Pattern.MULTILINE
        )
        
        // ============================================
        // Patterns pour Smali (bytecode Android)
        // ============================================
        
        // AES/ECB en Smali - détecte les appels à Cipher.getInstance avec AES/ECB
        private val SMALI_AES_ECB_PATTERN = Pattern.compile(
            "(const-string[^\"]*\"AES/ECB|const-string[^\"]*\"AES\"[^}]*invoke-static[^}]*Ljavax/crypto/Cipher;->getInstance)",
            Pattern.MULTILINE or Pattern.DOTALL
        )
        
        // AES sans padding en Smali
        private val SMALI_AES_NO_PADDING_PATTERN = Pattern.compile(
            "const-string[^\"]*\"AES/[^/]+/NoPadding\"",
            Pattern.MULTILINE
        )
        
        // Random faible en Smali - java/util/Random au lieu de java/security/SecureRandom
        private val SMALI_WEAK_RANDOM_PATTERN = Pattern.compile(
            "(Ljava/util/Random;|invoke-direct[^}]*Ljava/util/Random;-><init>)",
            Pattern.MULTILINE
        )
        
        // MD5 en Smali
        private val SMALI_MD5_PATTERN = Pattern.compile(
            "(const-string[^\"]*\"MD5\"|invoke-static[^}]*MessageDigest;->getInstance[^}]*\"MD5\")",
            Pattern.MULTILINE
        )
        
        // SHA-1 en Smali
        private val SMALI_SHA1_PATTERN = Pattern.compile(
            "(const-string[^\"]*\"SHA-?1\"|invoke-static[^}]*MessageDigest;->getInstance[^}]*\"SHA-?1\")",
            Pattern.MULTILINE
        )
        
        // DES faible en Smali (bonus)
        private val SMALI_DES_PATTERN = Pattern.compile(
            "const-string[^\"]*\"DES[/\"]",
            Pattern.MULTILINE
        )
        
        // Hardcoded keys en Smali (clés de chiffrement en dur)
        private val SMALI_HARDCODED_KEY_PATTERN = Pattern.compile(
            "(const-string[^\"]*\"[A-Fa-f0-9]{32,}\"[^}]*SecretKeySpec|Ljavax/crypto/spec/SecretKeySpec;)",
            Pattern.MULTILINE or Pattern.DOTALL
        )
    }
    
    /**
     * Scanne un dossier récursivement et détecte toutes les vulnérabilités.
     * 
     * @param directoryPath Chemin du dossier à scanner
     * @return Liste des vulnérabilités détectées
     * @throws IOException Si une erreur survient lors de la lecture des fichiers
     */
    @Throws(IOException::class)
    fun scanDirectory(directoryPath: String): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val path = Paths.get(directoryPath)
        
        if (!Files.exists(path) || !Files.isDirectory(path)) {
            throw IllegalArgumentException("Le chemin spécifié n'existe pas ou n'est pas un dossier : $directoryPath")
        }
        
        log.info("Démarrage du scan du dossier : {}", directoryPath)
        
        Files.walk(path)
            .filter { Files.isRegularFile(it) }
            .filter { isSupportedFile(it) }
            .forEach { file ->
                try {
                    vulnerabilities.addAll(scanFile(file.toFile()))
                } catch (e: IOException) {
                    log.error("Erreur lors du scan du fichier {} : {}", file, e.message)
                }
            }
        
        log.info("Scan terminé. {} vulnérabilités détectées.", vulnerabilities.size)
        return vulnerabilities
    }
    
    /**
     * Vérifie si un fichier est supporté par le scanner.
     */
    private fun isSupportedFile(file: java.nio.file.Path): Boolean {
        val fileName = file.toString().lowercase()
        return SUPPORTED_EXTENSIONS.any { fileName.endsWith(it) }
    }
    
    /**
     * Scanne un fichier unique et retourne les vulnérabilités détectées.
     */
    @Throws(IOException::class)
    private fun scanFile(file: File): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val filePath = file.absolutePath
        val isSmaliFile = filePath.lowercase().endsWith(".smali")
        
        if (isSmaliFile) {
            // Pour les fichiers Smali, on lit tout le contenu car les patterns peuvent s'étendre sur plusieurs lignes
            vulnerabilities.addAll(scanSmaliFile(file))
        } else {
            // Pour les autres fichiers, on scanne ligne par ligne
            vulnerabilities.addAll(scanSourceFile(file))
        }
        
        return vulnerabilities
    }
    
    /**
     * Scanne un fichier source (Java, Kotlin, Python, etc.) ligne par ligne.
     */
    @Throws(IOException::class)
    private fun scanSourceFile(file: File): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val filePath = file.absolutePath
        
        file.bufferedReader().use { reader ->
            var lineNumber = 0
            
            reader.forEachLine { line ->
                lineNumber++
                
                // Détecter AES/ECB
                if (AES_ECB_PATTERN.matcher(line).find()) {
                    vulnerabilities.add(createVulnerability(
                        filePath, lineNumber, VulnerabilityType.AES_ECB_USAGE, line
                    ))
                }
                
                // Détecter AES sans padding
                if (AES_NO_PADDING_PATTERN.matcher(line).find()) {
                    vulnerabilities.add(createVulnerability(
                        filePath, lineNumber, VulnerabilityType.AES_NO_PADDING, line
                    ))
                }
                
                // Détecter générateur aléatoire faible
                if (WEAK_RANDOM_PATTERN.matcher(line).find() && 
                    !line.contains("SecureRandom") && 
                    !line.contains("import java.security")) {
                    vulnerabilities.add(createVulnerability(
                        filePath, lineNumber, VulnerabilityType.WEAK_RANDOM_GENERATOR, line
                    ))
                }
                
                // Détecter MD5
                if (MD5_PATTERN.matcher(line).find()) {
                    vulnerabilities.add(createVulnerability(
                        filePath, lineNumber, VulnerabilityType.MD5_USAGE, line
                    ))
                }
                
                // Détecter SHA-1
                if (SHA1_PATTERN.matcher(line).find()) {
                    vulnerabilities.add(createVulnerability(
                        filePath, lineNumber, VulnerabilityType.SHA1_USAGE, line
                    ))
                }
            }
        }
        
        return vulnerabilities
    }
    
    /**
     * Scanne un fichier Smali (bytecode Android décompilé).
     * Les patterns Smali peuvent s'étendre sur plusieurs lignes.
     */
    @Throws(IOException::class)
    private fun scanSmaliFile(file: File): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val filePath = file.absolutePath
        val content = file.readText()
        val lines = content.lines()
        
        // Fonction helper pour trouver le numéro de ligne d'un match
        fun findLineNumber(matchStart: Int): Int {
            var lineNum = 1
            var pos = 0
            for (line in lines) {
                if (pos + line.length >= matchStart) {
                    return lineNum
                }
                pos += line.length + 1 // +1 pour le \n
                lineNum++
            }
            return lineNum
        }
        
        // Détecter AES/ECB en Smali
        var matcher = SMALI_AES_ECB_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.AES_ECB_USAGE, snippet
            ))
        }
        
        // Détecter AES sans padding en Smali
        matcher = SMALI_AES_NO_PADDING_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.AES_NO_PADDING, snippet
            ))
        }
        
        // Détecter Random faible en Smali (ignorer si SecureRandom est aussi présent)
        if (!content.contains("Ljava/security/SecureRandom;")) {
            matcher = SMALI_WEAK_RANDOM_PATTERN.matcher(content)
            while (matcher.find()) {
                val lineNum = findLineNumber(matcher.start())
                val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
                vulnerabilities.add(createVulnerability(
                    filePath, lineNum, VulnerabilityType.WEAK_RANDOM_GENERATOR, snippet
                ))
            }
        }
        
        // Détecter MD5 en Smali
        matcher = SMALI_MD5_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.MD5_USAGE, snippet
            ))
        }
        
        // Détecter SHA-1 en Smali
        matcher = SMALI_SHA1_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.SHA1_USAGE, snippet
            ))
        }
        
        // Détecter DES faible en Smali
        matcher = SMALI_DES_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.DES_USAGE, snippet
            ))
        }
        
        // Détecter clés hardcodées en Smali
        matcher = SMALI_HARDCODED_KEY_PATTERN.matcher(content)
        while (matcher.find()) {
            val lineNum = findLineNumber(matcher.start())
            val snippet = lines.getOrElse(lineNum - 1) { matcher.group() }.trim()
            vulnerabilities.add(createVulnerability(
                filePath, lineNum, VulnerabilityType.HARDCODED_KEY, snippet
            ))
        }
        
        log.debug("Fichier Smali scanné: {} - {} vulnérabilités", filePath, vulnerabilities.size)
        return vulnerabilities
    }
    
    /**
     * Crée un objet Vulnerability à partir des informations détectées.
     */
    private fun createVulnerability(
        filePath: String,
        lineNumber: Int,
        type: VulnerabilityType,
        codeSnippet: String
    ): Vulnerability {
        return Vulnerability(
            file = filePath,
            line = lineNumber,
            vulnerability = type.description,
            cwe = type.cwe,
            recommendation = type.recommendation,
            codeSnippet = codeSnippet.trim()
        )
    }
}

