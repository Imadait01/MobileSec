import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

/**
 * Middleware de logging des requêtes
 */
export const requestLogger = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const startTime = Date.now();

  // Capturer les informations de la requête
  const requestInfo = {
    method: req.method,
    path: req.path,
    query: Object.keys(req.query).length > 0 ? req.query : undefined,
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.get('user-agent')
  };

  // Logger la requête entrante
  logger.info('Incoming request', requestInfo);

  // Écouter la fin de la réponse
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const responseInfo = {
      ...requestInfo,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    };

    // Logger selon le code de statut
    if (res.statusCode >= 500) {
      logger.error('Request completed with server error', responseInfo);
    } else if (res.statusCode >= 400) {
      logger.warn('Request completed with client error', responseInfo);
    } else {
      logger.info('Request completed', responseInfo);
    }
  });

  next();
};

/**
 * Middleware de logging des erreurs non capturées
 */
export const errorLogger = (
  err: Error,
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  next(err);
};
