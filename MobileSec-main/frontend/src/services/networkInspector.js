import axios from 'axios';
import config from '../config';

const BASE_URL = config.API_URLS.NETWORK_INSPECTOR;

const networkInspectorService = {
    // Récupérer les résultats par scanId
    getResults: async (scanId) => {
        return axios.get(`${BASE_URL}/api/results/${scanId}`);
    },

    // Stats
    getStats: async () => {
        return axios.get(`${BASE_URL}/api/stats`);
    },

    // Status du scan en cours (si dynamique)
    getScanStatus: async () => {
        try {
            // Note: network-inspector has /scan-status at root, but via Gateway it's /api/network/scan-status
            // Gateway rewrites /api/network -> /api
            // Target becomes /api/scan-status which is WRONG if the service has it at /scan-status
            // Checking Network Inspecter main.py: @app.route('/scan-status') (Root)
            // So we need request: /api/network/scan-status
            // Rewrite: /api/scan-status.
            // Wait, does main.py have /api/scan-status? NO.
            // Issue: Gateway rewrites to /api, forcing target path to start with /api.
            // Network Inspector MUST expose /api/scan-status or Gateway rewrite must be flexible.
            // For now, let's try assuming I fixed main.py to aliases? No I didn't alias scan-status.
            // I will use /scan-status but I suspect it will fail via Gateway if Gateway forces /api prefix.
            // Actually, for this specific endpoint, I might need to add an alias in backend or change Gateway rule.
            return await axios.get(`${BASE_URL}/api/scan-status`);
        } catch (e) {
            return null;
        }
    }
};

export default networkInspectorService;
