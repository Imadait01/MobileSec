package com.cryptocheck.consumer

import com.cryptocheck.service.ScanService
import org.json.JSONObject
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.stereotype.Service

@Service
class ScanKafkaConsumer(val scanService: ScanService) {

    @KafkaListener(topics = ["scan-requests"], groupId = "cryptocheck-group")
    fun listen(record: ConsumerRecord<String, String>) {
        val data = JSONObject(record.value())
        val scanId = data.optString("id")
        if (scanId.isNotEmpty()) {
            println("[Kafka] Received scan request for scan_id: $scanId")
            try {
                scanService.analyzeFromMongo(scanId)
            } catch (e: Exception) {
                println("Erreur lors de l'analyse automatique pour scan_id $scanId : ${e.message}")
            }
        }
    }
}
