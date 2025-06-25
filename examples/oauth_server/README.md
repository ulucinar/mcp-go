# OAuth-Protected MCP Server

This example demonstrates an MCP server that requires OAuth authentication using **local JWT validation** with Keycloak's public keys.

## Features

- **Local JWT Validation**: Validates JWT tokens using Keycloak's public keys (JWKS endpoint)
- **No Network Calls for Validation**: Efficient token validation without introspection requests
- **Custom TLS Configuration**: Supports self-signed certificates via CA bundle
- **Protected MCP Endpoint**: Requires Bearer token authentication for all MCP operations
- **Single `hello` Tool**: Returns "HO" when called by authenticated users
- **Comprehensive Logging**: Tracks all authenticated requests and user activity
- **JWKS Caching**: Caches public keys for 5 minutes to improve performance

## How It Works

### JWT Validation Process

1. **JWKS Fetching**: Server fetches Keycloak's public keys from the JWKS endpoint on startup
2. **Token Parsing**: Incoming JWT tokens are parsed and their signatures verified using the public keys
3. **Claims Validation**: Standard JWT claims (exp, iat, iss, etc.) are validated
4. **User Context**: Validated user information is added to the request context

### Why Local Validation?

- **Performance**: No network calls needed for each token validation
- **Reliability**: Doesn't depend on Keycloak availability for each request
- **Security**: Same level of security as introspection (JWT signatures are cryptographically secure)
- **Scalability**: Better performance under high load

## Prerequisites

1. **Keycloak Server**: Running at `https://localhost:8443/realms/master`
2. **OAuth Client**: A client configured in Keycloak (client ID can be `example-app`)
3. **CA Certificate**: `keycloak-ca.pem` file in this directory (for self-signed certificates)

## Setup

### 1. Keycloak Configuration

Make sure your Keycloak server has:
- A realm (this example uses `master` realm)
- An OAuth client configured to issue JWT tokens
- The client should support `authorization_code` grant type
- JWKS endpoint accessible at `/protocol/openid-connect/certs`

### 2. CA Certificate (if using self-signed certificates)

Place your Keycloak server's CA certificate as `keycloak-ca.pem` in this directory:

```bash
# If you have the CA certificate from Keycloak
cp /path/to/keycloak-ca.pem examples/oauth_server/keycloak-ca.pem
```

### 3. Run the Server

```bash
cd examples/oauth_server
go run main.go
```

The server will start on `:8090` with the following endpoints:

- `POST /mcp` - Protected MCP endpoint (requires Bearer token)
- `GET /.well-known/oauth-protected-resource` - OAuth metadata for clients
- `GET /health` - Health check (unprotected)

## Testing

### 1. Get an Access Token from Keycloak

```bash
# Replace with your actual Keycloak configuration
CLIENT_ID="example-app"
KEYCLOAK_URL="https://localhost:8443/realms/master"

# Get authorization code (open in browser)
echo "Visit: ${KEYCLOAK_URL}/protocol/openid-connect/auth?client_id=${CLIENT_ID}&response_type=code&redirect_uri=http://localhost:8085/oauth/callback&scope=openid%20profile%20email"

# Exchange code for token (after getting code from redirect)
curl -k -X POST "${KEYCLOAK_URL}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:8085/oauth/callback"
```

### 2. Use MCP Client

Use the OAuth-enabled MCP client in `../oauth_client/` which is configured to work with this server.

```bash
cd ../oauth_client
go run main.go
```

### 3. Manual Testing

You can also test the server directly:

```bash
# Test without token (should fail)
curl -X POST http://localhost:8090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Test with valid token (should succeed)
curl -X POST http://localhost:8090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello","arguments":{}}}'
```

## Configuration

### Environment Variables

The server currently uses hardcoded configuration, but you can modify the constants in `main.go`:

```go
const (
    keycloakBaseURL = "https://localhost:8443/realms/master"  // Your Keycloak realm
    serverPort     = ":8090"                                  // Server port
    keycloakCAFile = "keycloak-ca.pem"                       // CA certificate file
)
```

### Security Considerations

1. **CA Certificate**: Always use proper CA certificates in production
2. **TLS**: Ensure all communication with Keycloak uses TLS
3. **Token Validation**: The server validates all standard JWT claims (exp, iat, iss)
4. **Key Rotation**: JWKS keys are refreshed every 5 minutes to handle key rotation

## Troubleshooting

### Common Issues

1. **"failed to fetch JWKS"**: Check if Keycloak is running and accessible
2. **"token signature is invalid"**: Verify the token was issued by the expected Keycloak instance
3. **"x509: certificate signed by unknown authority"**: Add the CA certificate to `keycloak-ca.pem`
4. **"token is expired"**: Obtain a fresh token from Keycloak

### Debug Logs

The server provides detailed logging for:
- JWKS fetching and caching
- Token validation attempts
- User authentication events
- MCP tool calls with user context

### Verify JWKS Endpoint

```bash
# Check if JWKS is accessible
curl -k https://localhost:8443/realms/master/protocol/openid-connect/certs
```

## Architecture

```
[MCP Client] 
    ↓ (HTTP + Bearer Token)
[OAuth Middleware] 
    ↓ (Validate JWT using JWKS)
[MCP Server] 
    ↓ (Process MCP calls)
[Hello Tool] → Returns "HO"
```

The JWT validation happens entirely locally using public keys, making it fast and reliable. 