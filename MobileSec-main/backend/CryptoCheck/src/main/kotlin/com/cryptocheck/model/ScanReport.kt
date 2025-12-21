package com.cryptocheck.model

import com.fasterxml.jackson.annotation.JsonInclude
import java.time.LocalDateTime

/**
 * Modèle représentant un rapport de scan complet.
 * 
 * Contient toutes les vulnérabilités détectées lors d'un scan,
 * ainsi que des métadonnées sur le scan.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ScanReport(
    /**
     * Chemin du dossier scanné.
     */
    val scannedPath: String,
    
    /**
     * Date et heure du scan.
     */
    val scanDate: LocalDateTime,
    
    /**
     * Nombre total de vulnérabilités détectées.
     */
    val totalVulnerabilities: Int,
    
    /**
     * Liste de toutes les vulnérabilités détectées.
     */
    val vulnerabilities: List<Vulnerability>,
    
    /**
     * Durée du scan en millisecondes.
     */
    val scanDurationMs: Long
)

