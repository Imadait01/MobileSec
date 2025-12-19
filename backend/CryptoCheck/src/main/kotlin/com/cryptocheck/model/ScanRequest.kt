package com.cryptocheck.model

import jakarta.validation.constraints.NotBlank

/**
 * Modèle de requête pour lancer un scan.
 */
data class ScanRequest(
    /**
     * Chemin du dossier à scanner.
     * Doit être un chemin valide et non vide.
     */
    @field:NotBlank(message = "Le chemin du dossier est requis")
    val directoryPath: String
)

