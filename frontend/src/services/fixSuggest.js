import axios from 'axios';
import config from '../config';

const API_URL = config.API_URLS.FIX_SUGGEST;

/**
 * Service pour interagir avec l'API FixSuggest
 */
const fixSuggestService = {
    /**
     * Génère ou récupère les suggestions pour un scan
     * @param {string} scanId - ID du scan
     * @param {boolean} regenerate - Forcer la régénération
     * @returns {Promise<Object>} - Réponse de l'API avec les suggestions
     */
    getSuggestions: async (scanId, regenerate = false) => {
        try {
            // Endpoint: /api/v1/suggest/scan/{scan_id}?regenerate={bool}
            const response = await axios.get(`${API_URL}/api/v1/suggest/scan/${scanId}`, {
                params: { regenerate }
            });
            return response.data;
        } catch (error) {
            console.error('Error fetching suggestions:', error);
            throw error;
        }
    },

    /**
     * Récupère uniquement les suggestions en cache
     * @param {string} scanId - ID du scan
     * @returns {Promise<Object>} - Réponse de l'API
     */
    getCachedSuggestions: async (scanId) => {
        try {
            const response = await axios.get(`${API_URL}/api/v1/suggest/scan/${scanId}/cached`);
            return response.data;
        } catch (error) {
            // 404 handled by caller usually
            throw error;
        }
    },

    /**
     * Récupère les vulnérabilités d'un scan (sans générer de suggestions)
     * @param {string} scanId - ID du scan
     * @returns {Promise<Object>} - Vulnérabilités du scan
     */
    getVulnerabilities: async (scanId) => {
        try {
            const response = await axios.get(`${API_URL}/api/v1/suggest/scan/${scanId}/vulnerabilities`);
            return response.data;
        } catch (error) {
            console.error('Error fetching vulnerabilities:', error);
            throw error;
        }
    },

    /**
     * Génère des suggestions avec priorité ML (LightGBM + Amazon Bedrock)
     * @param {string} scanId - ID du scan
     * @param {number} maxSuggestions - Nombre max de suggestions (défaut: 10)
     * @returns {Promise<Object>} - Suggestions avec scores ML
     */
    getMLPrioritizedSuggestions: async (scanId, maxSuggestions = 10) => {
        try {
            // 1. Récupérer les vulnérabilités du scan
            const vulnData = await axios.get(`${API_URL}/api/v1/suggest/scan/${scanId}/vulnerabilities`);
            const vulnerabilities = vulnData.data.vulnerabilities;

            if (!vulnerabilities || vulnerabilities.length === 0) {
                return {
                    status: 'no_vulnerabilities',
                    scan_id: scanId,
                    suggestions: [],
                    total_processed: 0,
                    total_suggestions: 0
                };
            }

            // 2. Appeler l'endpoint ML-priority
            const response = await axios.post(
                `${API_URL}/api/v1/suggest/ml-priority`,
                {
                    scan_id: scanId,
                    vulnerabilities: vulnerabilities,
                    language: 'java',
                    include_patches: true
                },
                {
                    params: { max_suggestions: maxSuggestions }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error fetching ML-prioritized suggestions:', error);
            throw error;
        }
    }
};

export default fixSuggestService;
