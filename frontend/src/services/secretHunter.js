import axios from 'axios';
import config from '../config';

const BASE_URL = config.API_URLS.SECRET_HUNTER;

const secretHunterService = {
    // Récupérer les résultats par scanId
    getResults: async (scanId) => {
        return axios.get(`${BASE_URL}/api/results/${scanId}`);
    },

    // Stats
    getStats: async () => {
        return axios.get(`${BASE_URL}/api/stats`);
    }
};

export default secretHunterService;
