package com.cryptocheck.controller

import com.cryptocheck.model.ScanReport
import com.cryptocheck.model.ScanRequest
import com.cryptocheck.service.ScanService
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import java.time.LocalDateTime
import org.mockito.kotlin.any
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Tests unitaires pour le contrôleur REST.
 */
@WebMvcTest(ScanController::class)
class ScanControllerTest {
    
    @Autowired
    private lateinit var mockMvc: MockMvc
    
    @MockBean
    private lateinit var scanService: ScanService
    
    @Autowired
    private lateinit var objectMapper: ObjectMapper
    
    @Test
    fun testScanEndpoint() {
        // Préparer le mock
        val mockReport = ScanReport(
            scannedPath = "/test/path",
            scanDate = LocalDateTime.now(),
            totalVulnerabilities = 2,
            vulnerabilities = emptyList(),
            scanDurationMs = 100L
        )
        
        whenever(scanService.scanDirectory(any())).thenReturn(mockReport)
        
        // Créer la requête
        val request = ScanRequest(directoryPath = "/test/path")
        
        // Exécuter la requête
        mockMvc.perform(
            post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.scannedPath").value("/test/path"))
            .andExpect(jsonPath("$.totalVulnerabilities").value(2))
        
        verify(scanService, times(1)).scanDirectory("/test/path")
    }
    
    @Test
    fun testScanEndpointWithInvalidPath() {
        whenever(scanService.scanDirectory(any()))
            .thenThrow(IllegalArgumentException("Chemin invalide"))
        
        val request = ScanRequest(directoryPath = "/invalid/path")
        
        mockMvc.perform(
            post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").exists())
    }
    
    @Test
    fun testGetReportEndpoint() {
        val mockReport = ScanReport(
            scannedPath = "/test/path",
            scanDate = LocalDateTime.now(),
            totalVulnerabilities = 1,
            vulnerabilities = emptyList(),
            scanDurationMs = 50L
        )
        
        whenever(scanService.getLastReport()).thenReturn(mockReport)
        
        mockMvc.perform(get("/api/report"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.scannedPath").value("/test/path"))
            .andExpect(jsonPath("$.totalVulnerabilities").value(1))
    }
    
    @Test
    fun testGetReportEndpointWhenNoReport() {
        whenever(scanService.getLastReport()).thenReturn(null)
        
        mockMvc.perform(get("/api/report"))
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.error").exists())
    }
    
    @Test
    fun testScanEndpointWithEmptyPath() {
        val request = ScanRequest(directoryPath = "")
        
        mockMvc.perform(
            post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isBadRequest)
    }
}

