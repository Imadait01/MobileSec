package com.cryptocheck

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import org.springframework.kafka.annotation.EnableKafka

/**
 * Application principale du scanner SAST pour vulnérabilités cryptographiques.
 * 
 * Cette application fournit une API REST pour scanner des dossiers de code
 * et détecter les vulnérabilités cryptographiques courantes.
 */

@SpringBootApplication
@ComponentScan(basePackages = ["com.cryptocheck"])
@EnableKafka
class CryptoCheckApplication

fun main(args: Array<String>) {
    runApplication<CryptoCheckApplication>(*args)
}

