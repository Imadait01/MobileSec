import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

/**
 * Middleware de gestion globale des erreurs
 */
export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Déterminer le code de statut
  const statusCode = err.statusCode || 500;
  const isOperational = err.isOperational ?? statusCode < 500;

  // Logger l'erreur
  if (statusCode >= 500) {
    logger.error('Internal server error', {
      error: err.message,
      stack: err.stack,
      path: req.path,
      method: req.method,
      body: req.body
    });
  } else {
    logger.warn('Client error', {
      error: err.message,
      path: req.path,
      method: req.method,
      statusCode
    });
  }

  // Envoyer la réponse
  res.status(statusCode).json({
    error: isOperational ? err.message : 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      details: err
    })
  });
};

/**
 * Middleware pour les routes non trouvées
 */
export const notFoundHandler = (
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  logger.warn('Route not found', { path: req.path, method: req.method });

  res.status(404).json({
    error: 'Not found',
    message: `Route ${req.method} ${req.path} does not exist`,
    availableEndpoints: [
      'GET /health',
      'POST /api/reports/generate',
      'GET /api/reports',
      'GET /api/reports/:reportId',
      'GET /api/reports/:reportId/download',
      'GET /api/reports/:reportId/vulnerabilities',
      'DELETE /api/reports/:reportId'
    ]
  });
};

/**
 * Créer une erreur opérationnelle
 */
export const createError = (message: string, statusCode: number): AppError => {
  const error = new Error(message) as AppError;
  error.statusCode = statusCode;
  error.isOperational = true;
  return error;
};
