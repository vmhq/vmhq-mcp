/**
 * OAuth 2.1 implementation for MCP servers. Public entry point.
 *
 * Importing this module triggers persisted-state load and the prune interval
 * (see ./oauth/state.ts). Implementation is split across:
 *   ./oauth/state.ts       – in-memory maps + disk persistence
 *   ./oauth/redirectUri.ts – RFC 8252 redirect URI validation/matching
 *   ./oauth/views.ts       – authorization form + success HTML
 *   ./oauth/endpoints.ts   – HTTP handlers + token verification
 */
export type { OAuthConfig } from "./oauth/endpoints.js";
export {
  OAUTH_CORS_HEADERS,
  authorizationServerMetadata,
  authorize,
  authorizeForm,
  exchangeToken,
  isOAuthAccessToken,
  mcpUrl,
  protectedResourceMetadata,
  registerClient,
  revokeToken,
  unauthorized,
  verifyAccessToken,
} from "./oauth/endpoints.js";
export {
  CLAUDE_WEB_AUTH_CALLBACK,
  canonicalRedirectUri,
} from "./oauth/redirectUri.js";
export {
  constantTimeEqual,
  pruneExpiredOAuthState,
  reloadPersistedOAuthState,
} from "./oauth/state.js";
