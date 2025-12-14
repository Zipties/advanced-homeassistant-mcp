/**
 * OIDC Token Validator
 *
 * Validates JWT tokens issued by Authelia (or any OIDC-compliant Authorization Server)
 * by verifying signatures against the JWKS endpoint.
 *
 * This is the core of OAuth 2.1 Resource Server functionality.
 */

import * as jose from "jose";
import { OAUTH_CONFIG } from "../config/oauth.config";
import { logger } from "../utils/logger";

// Type definitions for token claims
export interface OIDCTokenClaims {
  // Standard JWT claims
  iss: string; // Issuer
  sub: string; // Subject (user ID)
  aud: string | string[]; // Audience
  exp: number; // Expiration time
  iat: number; // Issued at
  nbf?: number; // Not before

  // OIDC standard claims
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  groups?: string[];

  // Authelia-specific claims
  amr?: string[]; // Authentication methods
  azp?: string; // Authorized party (client_id)
  at_hash?: string; // Access token hash
  auth_time?: number; // Time of authentication
}

export interface TokenValidationResult {
  valid: boolean;
  claims?: OIDCTokenClaims;
  error?: string;
  errorCode?: "invalid_token" | "expired_token" | "invalid_audience" | "invalid_issuer" | "jwks_error";
}

/**
 * OIDC Validator singleton for token validation
 */
class OIDCValidatorImpl {
  private jwks: jose.GetKeyFunction<jose.JWSHeaderParameters, jose.FlattenedJWSInput> | null = null;
  private jwksUri: string = "";
  private issuer: string = "";
  private resourceServerUri: string = "";
  private clockTolerance: number = 60;
  private audienceValidation: boolean = true;
  private initialized: boolean = false;

  /**
   * Initialize the validator with configuration
   * Must be called before validating tokens
   */
  async initialize(): Promise<void> {
    if (!OAUTH_CONFIG.ENABLED) {
      logger.info("OAuth is disabled, skipping OIDC validator initialization");
      return;
    }

    this.jwksUri = OAUTH_CONFIG.JWKS_URI;
    this.issuer = OAUTH_CONFIG.ISSUER;
    this.resourceServerUri = OAUTH_CONFIG.RESOURCE_SERVER_URI;
    this.clockTolerance = OAUTH_CONFIG.CLOCK_TOLERANCE;
    this.audienceValidation = OAUTH_CONFIG.AUDIENCE_VALIDATION;

    try {
      // Create remote JWKS set for signature verification
      // jose automatically handles key rotation and caching
      this.jwks = jose.createRemoteJWKSet(new URL(this.jwksUri));
      this.initialized = true;
      logger.info(`OIDC validator initialized with JWKS from ${this.jwksUri}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      logger.error(`Failed to initialize OIDC validator: ${message}`);
      throw new Error(`OIDC validator initialization failed: ${message}`);
    }
  }

  /**
   * Validate an access token against the JWKS
   */
  async validateToken(token: string): Promise<TokenValidationResult> {
    if (!this.initialized || !this.jwks) {
      return {
        valid: false,
        error: "OIDC validator not initialized",
        errorCode: "jwks_error",
      };
    }

    if (!token || typeof token !== "string") {
      return {
        valid: false,
        error: "Token is required",
        errorCode: "invalid_token",
      };
    }

    // Remove "Bearer " prefix if present
    const cleanToken = token.startsWith("Bearer ") ? token.slice(7) : token;

    try {
      // Build verification options
      const verifyOptions: jose.JWTVerifyOptions = {
        issuer: this.issuer,
        clockTolerance: this.clockTolerance,
      };

      // Add audience validation if enabled (RFC 8707)
      if (this.audienceValidation && this.resourceServerUri) {
        verifyOptions.audience = this.resourceServerUri;
      }

      // Verify the token signature and claims
      const { payload } = await jose.jwtVerify(cleanToken, this.jwks, verifyOptions);

      // Extract and type the claims
      const claims = payload as unknown as OIDCTokenClaims;

      logger.debug(`Token validated for subject: ${claims.sub}`);

      return {
        valid: true,
        claims,
      };
    } catch (error) {
      return this.handleValidationError(error);
    }
  }

  /**
   * Handle validation errors and return appropriate error codes
   */
  private handleValidationError(error: unknown): TokenValidationResult {
    if (error instanceof jose.errors.JWTExpired) {
      logger.debug("Token validation failed: expired");
      return {
        valid: false,
        error: "Token has expired",
        errorCode: "expired_token",
      };
    }

    if (error instanceof jose.errors.JWTClaimValidationFailed) {
      const message = error.message;
      logger.debug(`Token validation failed: ${message}`);

      if (message.includes("audience")) {
        return {
          valid: false,
          error: "Token audience mismatch",
          errorCode: "invalid_audience",
        };
      }

      if (message.includes("issuer")) {
        return {
          valid: false,
          error: "Token issuer mismatch",
          errorCode: "invalid_issuer",
        };
      }

      return {
        valid: false,
        error: `Token claim validation failed: ${message}`,
        errorCode: "invalid_token",
      };
    }

    if (error instanceof jose.errors.JWSSignatureVerificationFailed) {
      logger.debug("Token validation failed: invalid signature");
      return {
        valid: false,
        error: "Invalid token signature",
        errorCode: "invalid_token",
      };
    }

    if (error instanceof jose.errors.JWKSNoMatchingKey) {
      logger.debug("Token validation failed: no matching key in JWKS");
      return {
        valid: false,
        error: "Token signed with unknown key",
        errorCode: "invalid_token",
      };
    }

    // Generic error
    const message = error instanceof Error ? error.message : "Unknown error";
    logger.error(`Token validation error: ${message}`);
    return {
      valid: false,
      error: `Token validation failed: ${message}`,
      errorCode: "invalid_token",
    };
  }

  /**
   * Check if the validator is initialized and ready
   */
  isReady(): boolean {
    return this.initialized && this.jwks !== null;
  }

  /**
   * Get the configured issuer for logging/debugging
   */
  getIssuer(): string {
    return this.issuer;
  }
}

// Singleton instance
let validatorInstance: OIDCValidatorImpl | null = null;

/**
 * Get the OIDC validator singleton
 */
export function getOIDCValidator(): OIDCValidatorImpl {
  if (!validatorInstance) {
    validatorInstance = new OIDCValidatorImpl();
  }
  return validatorInstance;
}

/**
 * Reset the validator (for testing purposes)
 */
export function resetOIDCValidator(): void {
  validatorInstance = null;
}
