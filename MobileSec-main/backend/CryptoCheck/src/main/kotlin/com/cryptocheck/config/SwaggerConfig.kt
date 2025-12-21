package com.cryptocheck.config

import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.servers.Server
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * Configuration Swagger/OpenAPI pour CryptoCheck
 * 
 * Swagger UI accessible sur: /swagger-ui.html
 * API Docs: /v3/api-docs
 */
@Configuration
class SwaggerConfig {
    
    @Bean
    fun customOpenAPI(): OpenAPI {
        return OpenAPI()
            .info(
                Info()
                    .title("CryptoCheck API")
                    .version("2.0.0")
                    .description("""
                        API pour la détection de vulnérabilités cryptographiques dans le code.
                        
                        **Fonctionnalités:**
                        - Analyse de code Java/Kotlin pour détecter les failles cryptographiques
                        - Détection d'algorithmes obsolètes (MD5, SHA1, DES, etc.)
                        - Détection de clés hardcodées
                        - Détection de générateurs aléatoires non sécurisés
                        
                        **Architecture:**
                        - Lit les données depuis MongoDB (collection: apk_results)
                        - Écrit les résultats dans MongoDB (collection: crypto_results)
                    """.trimIndent())
                    .contact(Contact().name("Security Platform Team"))
            )
            .servers(listOf(
                Server().url("http://localhost:8080").description("Serveur de développement"),
                Server().url("http://crypto-check:8080").description("Serveur Docker")
            ))
    }
}
