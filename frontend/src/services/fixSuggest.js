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
            // FixSuggest exposes routes under /api/v1 (main includes prefix '/api/v1')
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
    }
};

export default fixSuggestService;
