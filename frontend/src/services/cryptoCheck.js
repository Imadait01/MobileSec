import axios from 'axios';
import config from '../config';

const BASE_URL = config.API_URLS.CRYPTO_CHECK;

const cryptoCheckService = {
    // Récupérer les résultats par scanId
    getResults: async (scanId) => {
        return axios.get(`${BASE_URL}/api/results/${scanId}`);
    },

    // Stats
    getStats: async () => {
        return axios.get(`${BASE_URL}/api/stats`);
    }
};

export default cryptoCheckService;
