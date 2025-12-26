const config = {
    // Direct URLs to microservices - bypassing API Gateway for now
    // to avoid routing issues
    API_URLS: {
        API_GATEWAY: 'http://localhost:8082',
        APK_SCANNER: 'http://localhost:5000',  // Direct connection
        SECRET_HUNTER: 'http://localhost:5002', // Direct connection
        NETWORK_INSPECTOR: 'http://localhost:5001', // Direct connection
        CRYPTO_CHECK: 'http://localhost:8084', // Direct connection
        FIX_SUGGEST: 'http://localhost:8000', // Direct connection
        REPORT_GEN: 'http://localhost:3005', // Direct connection
        ML_MODEL: 'http://localhost:8001', // Direct connection
    }
};

export default config;
