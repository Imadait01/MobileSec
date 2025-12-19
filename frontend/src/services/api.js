import axios from 'axios';

// Instance par défaut (si on passait tout par API Gateway)
const api = axios.create({
    headers: {
        'Content-Type': 'application/json',
    },
    timeout: 30000, // 30s timeout
});

// Intercepteur pour gérer les erreurs globalement
api.interceptors.response.use(
    (response) => response,
    (error) => {
        console.error('API Error:', error.response || error.message);
        return Promise.reject(error);
    }
);

export default api;
