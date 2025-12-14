/**
 * OAuth 2.1 Resource Server Middleware
 *
 * Implements RFC 9728 Protected Resource Metadata and OAuth token validation
 * for Claude.ai remote MCP connector compatibility.
 */

import { Request, Response, NextFunction, Router } from "express";
import { OAUTH_CONFIG, getProtectedResourceMetadata } from "../config/oauth.config";
import { getOIDCValidator, OIDCTokenClaims } from "../security/oidc-validator";
import { logger } from "../utils/logger";

// Extend Express Request to include OAuth user info
declare global {
  namespace Express {
    interface Request {
      oauth?: {
        claims: OIDCTokenClaims;
        token: string;
      };
    }
  }
}

// Paths that should bypass OAuth authentication
const PUBLIC_PATHS = [
  "/health",
  "/ready",
  "/.well-known/oauth-protected-resource",
  "/.well-known/mcp-config",
];

/**
 * Build the WWW-Authenticate header value for 401 responses
 * See RFC 6750 Section 3 for format specification
 */
function buildWWWAuthenticateHeader(
  error?: string,
  errorDescription?: string
): string {
  const parts = [
    `Bearer realm="${OAUTH_CONFIG.RESOURCE_SERVER_URI || "mcp"}"`,
  ];

  // Add resource indicator (RFC 8707)
  if (OAUTH_CONFIG.RESOURCE_SERVER_URI) {
    parts.push(`resource="${OAUTH_CONFIG.RESOURCE_SERVER_URI}"`);
  }

  // Add error info if present
  if (error) {
    parts.push(`error="${error}"`);
    if (errorDescription) {
      // Escape quotes in description
      const safeDescription = errorDescription.replace(/"/g, '\\"');
      parts.push(`error_description="${safeDescription}"`);
    }
  }

  return parts.join(", ");
}

/**
 * Create router for OAuth discovery endpoints
 */
export function createOAuthDiscoveryRouter(): Router {
  const router = Router();

  // RFC 9728: Protected Resource Metadata
  router.get("/.well-known/oauth-protected-resource", (_req: Request, res: Response) => {
    const metadata = getProtectedResourceMetadata();
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(metadata);
    logger.debug("Served OAuth protected resource metadata");
  });

  return router;
}

/**
 * OAuth authentication middleware
 * Validates Bearer tokens against Authelia JWKS
 */
export async function oauthAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // Skip auth for public paths
  const isPublicPath = PUBLIC_PATHS.some(
    (path) => req.path === path || req.path.startsWith("/.well-known/")
  );

  if (isPublicPath) {
    return next();
  }

  // Get Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.status(401)
      .setHeader("WWW-Authenticate", buildWWWAuthenticateHeader())
      .json({
        success: false,
        error: "unauthorized",
        message: "Authentication required",
        timestamp: new Date().toISOString(),
      });
    return;
  }

  // Validate Bearer token format
  if (!authHeader.startsWith("Bearer ")) {
    res.status(401)
      .setHeader(
        "WWW-Authenticate",
        buildWWWAuthenticateHeader("invalid_request", "Authorization header must use Bearer scheme")
      )
      .json({
        success: false,
        error: "invalid_request",
        message: "Authorization header must use Bearer scheme",
        timestamp: new Date().toISOString(),
      });
    return;
  }

  const token = authHeader.slice(7); // Remove "Bearer "

  // Validate token against JWKS
  const validator = getOIDCValidator();
  const result = await validator.validateToken(token);

  if (!result.valid) {
    // Map error codes to RFC 6750 error codes
    let error = "invalid_token";
    if (result.errorCode === "expired_token") {
      error = "invalid_token"; // RFC 6750 uses invalid_token for expired
    }

    logger.debug(`OAuth authentication failed: ${result.error}`);

    res.status(401)
      .setHeader(
        "WWW-Authenticate",
        buildWWWAuthenticateHeader(error, result.error)
      )
      .json({
        success: false,
        error,
        message: result.error || "Token validation failed",
        timestamp: new Date().toISOString(),
      });
    return;
  }

  // Attach user info to request
  req.oauth = {
    claims: result.claims!,
    token,
  };

  logger.debug(`OAuth authentication successful for user: ${result.claims?.sub}`);
  next();
}

/**
 * Factory function to create the OAuth middleware
 * Returns a no-op middleware if OAuth is disabled
 */
export function createOAuthMiddleware(): (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void> | void {
  if (!OAUTH_CONFIG.ENABLED) {
    logger.info("OAuth is disabled, authentication middleware bypassed");
    return (_req: Request, _res: Response, next: NextFunction) => next();
  }

  return oauthAuthMiddleware;
}

/**
 * Middleware to require specific scopes
 * Use after oauthAuthMiddleware
 */
export function requireScopes(...requiredScopes: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!OAUTH_CONFIG.ENABLED) {
      return next();
    }

    if (!req.oauth) {
      res.status(401)
        .setHeader("WWW-Authenticate", buildWWWAuthenticateHeader())
        .json({
          success: false,
          error: "unauthorized",
          message: "Authentication required",
          timestamp: new Date().toISOString(),
        });
      return;
    }

    // TODO: Implement scope checking if needed
    // For now, we trust that the token was issued with appropriate scopes
    // Authelia handles scope validation during token issuance

    next();
  };
}
