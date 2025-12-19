const config = {
    // En production, ces URLs pourraient venir de variables d'environnement
    API_URLS: {
        API_GATEWAY: process.env.REACT_APP_API_GATEWAY_URL || 'http://localhost:8082',
        APK_SCANNER: process.env.REACT_APP_APK_SCANNER_URL || 'http://localhost:5000',
        SECRET_HUNTER: process.env.REACT_APP_SECRET_HUNTER_URL || 'http://localhost:5002',
        NETWORK_INSPECTOR: process.env.REACT_APP_NETWORK_INSPECTOR_URL || 'http://localhost:5001',
        CRYPTO_CHECK: process.env.REACT_APP_CRYPTO_CHECK_URL || 'http://localhost:8084',
        FIX_SUGGEST: process.env.REACT_APP_FIX_SUGGEST_URL || 'http://localhost:8000',
        REPORT_GEN: process.env.REACT_APP_REPORT_GEN_URL || 'http://localhost:8082/api/report',
    }
};

export default config;
