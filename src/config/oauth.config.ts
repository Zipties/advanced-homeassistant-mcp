/**
 * OAuth 2.1 Resource Server Configuration
 *
 * This server acts as an OAuth Resource Server that validates tokens issued
 * by Authelia (the Authorization Server). It does NOT issue tokens itself.
 *
 * Required for Claude.ai remote MCP connector compatibility.
 */

// OAuth 2.1 Resource Server Configuration
export const OAUTH_CONFIG = {
  // Master switch for OAuth mode
  ENABLED: process.env.OAUTH_ENABLED === "true",

  // Authorization Server (Authelia) configuration
  ISSUER: process.env.OAUTH_ISSUER || "",
  JWKS_URI: process.env.OAUTH_JWKS_URI || "",

  // Resource Server identity (this server)
  RESOURCE_SERVER_URI: process.env.OAUTH_RESOURCE_SERVER_URI || "",

  // Token validation settings
  AUDIENCE_VALIDATION: process.env.OAUTH_AUDIENCE_VALIDATION !== "false", // default true
  CLOCK_TOLERANCE: parseInt(process.env.OAUTH_CLOCK_TOLERANCE || "60", 10), // seconds

  // Supported scopes (for metadata endpoint)
  SCOPES_SUPPORTED: ["openid", "profile", "email", "groups"],

  // Bearer token methods (for metadata endpoint)
  BEARER_METHODS_SUPPORTED: ["header"],
};

// Validate OAuth configuration when enabled
export function validateOAuthConfig(): void {
  if (!OAUTH_CONFIG.ENABLED) {
    return; // Skip validation if OAuth is disabled
  }

  const missingVars: string[] = [];

  if (!OAUTH_CONFIG.ISSUER) {
    missingVars.push("OAUTH_ISSUER");
  }
  if (!OAUTH_CONFIG.JWKS_URI) {
    missingVars.push("OAUTH_JWKS_URI");
  }
  if (!OAUTH_CONFIG.RESOURCE_SERVER_URI) {
    missingVars.push("OAUTH_RESOURCE_SERVER_URI");
  }

  if (missingVars.length > 0) {
    throw new Error(
      `OAuth is enabled but missing required environment variables: ${missingVars.join(", ")}\n` +
        "Required variables:\n" +
        "  OAUTH_ISSUER - Authorization server URL (e.g., https://authelia.example.com)\n" +
        "  OAUTH_JWKS_URI - JWKS endpoint URL (e.g., https://authelia.example.com/jwks.json)\n" +
        "  OAUTH_RESOURCE_SERVER_URI - This server's public URL (e.g., https://ha-mcp.example.com)"
    );
  }
}

// OAuth Protected Resource Metadata (RFC 9728)
export function getProtectedResourceMetadata(): object {
  return {
    resource: OAUTH_CONFIG.RESOURCE_SERVER_URI,
    authorization_servers: [OAUTH_CONFIG.ISSUER],
    scopes_supported: OAUTH_CONFIG.SCOPES_SUPPORTED,
    bearer_methods_supported: OAUTH_CONFIG.BEARER_METHODS_SUPPORTED,
  };
}
