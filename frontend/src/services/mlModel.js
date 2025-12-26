import axios from 'axios';
import config from '../config';

const API_URL = config.API_URLS.ML_MODEL || 'http://localhost:8001';

/**
 * Service pour interagir avec l'API ML Model
 */
const mlModelService = {
    /**
     * Obtient les suggestions ML pour un scan
     * @param {string} scanId - ID du scan
     * @param {number} topK - Nombre de suggestions à retourner
     * @returns {Promise<Object>} - Réponse de l'API avec les suggestions ML
     */
    getPredictions: async (scanId, topK = 3) => {
        try {
            const response = await axios.post(`${API_URL}/api/v1/predict/${scanId}?top_k=${topK}`);
            return response.data;
        } catch (error) {
            console.error('Error fetching ML predictions:', error);
            throw error;
        }
    },

    /**
     * Obtient les informations sur le modèle ML
     * @returns {Promise<Object>} - Métadonnées du modèle
     */
    getModelInfo: async () => {
        try {
            const response = await axios.get(`${API_URL}/api/v1/model/info`);
            return response.data;
        } catch (error) {
            console.error('Error fetching model info:', error);
            throw error;
        }
    },

    /**
     * Vérifie la santé du service ML
     * @returns {Promise<Object>} - Status du service
     */
    healthCheck: async () => {
        try {
            const response = await axios.get(`${API_URL}/health`);
            return response.data;
        } catch (error) {
            console.error('ML service health check failed:', error);
            throw error;
        }
    }
};

export default mlModelService;
