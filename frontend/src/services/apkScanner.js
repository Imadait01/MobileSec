import axios from 'axios';
import config from '../config';

const BASE_URL = config.API_URLS.APK_SCANNER;

const apkScannerService = {
    // Lancer un scan (Upload)
    scanFile: async (file, force = false, onUploadProgress) => {
        const formData = new FormData();
        formData.append('file', file);

        return axios.post(`${BASE_URL}/api/scan?force=${force}`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
            onUploadProgress,
        });
    },

    // Récupérer les résultats d'un scan
    getResults: async (scanId) => {
        return axios.get(`${BASE_URL}/api/results/${scanId}`);
    },

    // Lister tous les résultats (pour l'historique)
    getAllResults: async (limit = 20) => {
        return axios.get(`${BASE_URL}/api/results?limit=${limit}`);
    },

    // Stats
    getStats: async () => {
        return axios.get(`${BASE_URL}/api/stats`);
    }
};

export default apkScannerService;
