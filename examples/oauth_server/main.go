package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// Keycloak configuration
	keycloakBaseURL     = "https://localhost:8443/realms/master"
	keycloakJWKSURL     = keycloakBaseURL + "/protocol/openid-connect/certs"
	keycloakMetadataURL = keycloakBaseURL + "/.well-known/openid-configuration"
	keycloakCAFile      = "keycloak-ca.pem"

	// Server configuration
	serverPort  = ":8090"
	mcpEndpoint = "/mcp"
)

// JWKSResponse represents Keycloak's JWKS response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
	Alg string   `json:"alg"`
}

// OAuthClaims holds the validated OAuth token information
type OAuthClaims struct {
	Subject  string
	Username string
	ClientID string
	Scopes   []string
	jwt.RegisteredClaims
}

// CustomClaims embeds both RegisteredClaims and our custom fields
type CustomClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string `json:"preferred_username"`
	ClientID          string `json:"azp"` // Authorized party (client_id)
	Scope             string `json:"scope"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// JWTValidator handles JWT token validation using Keycloak's public keys
type JWTValidator struct {
	httpClient  *http.Client
	jwksCache   map[string]*jwt.Token
	cacheMutex  sync.RWMutex
	lastFetched time.Time
	jwks        *JWKSResponse
}

// NewJWTValidator creates a new JWT validator with custom TLS configuration
func NewJWTValidator() (*JWTValidator, error) {
	// Create custom TLS configuration
	tlsConfig := &tls.Config{}

	// Try to load the CA certificate if it exists
	if _, err := os.Stat(keycloakCAFile); err == nil {
		caCert, err := os.ReadFile(keycloakCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
		log.Printf("Loaded custom CA certificate from %s", keycloakCAFile)
	} else {
		log.Printf("Warning: CA certificate not found at %s, using system CA bundle", keycloakCAFile)
		log.Printf("If using self-signed certificates, add the CA certificate to %s", keycloakCAFile)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	validator := &JWTValidator{
		httpClient:  httpClient,
		jwksCache:   make(map[string]*jwt.Token),
		lastFetched: time.Time{},
	}

	// Fetch JWKS on startup
	if err := validator.fetchJWKS(); err != nil {
		log.Printf("Warning: Failed to fetch JWKS on startup: %v", err)
		log.Printf("Token validation will fail until JWKS can be fetched")
	}

	return validator, nil
}

// fetchJWKS fetches the JSON Web Key Set from Keycloak
func (v *JWTValidator) fetchJWKS() error {
	// Only fetch if we haven't fetched recently (cache for 5 minutes)
	if time.Since(v.lastFetched) < 5*time.Minute && v.jwks != nil {
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, keycloakJWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	v.jwks = &jwks
	v.lastFetched = time.Now()
	log.Printf("Successfully fetched JWKS with %d keys", len(jwks.Keys))

	return nil
}

// getSigningKey returns the signing key for a given token
func (v *JWTValidator) getSigningKey(token *jwt.Token) (interface{}, error) {
	// Ensure we have fresh JWKS
	if err := v.fetchJWKS(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Get the kid from token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Find the matching key
	for _, key := range v.jwks.Keys {
		if key.Kid == kid {
			// For RSA keys, we need to construct the public key
			if key.Kty == "RSA" {
				return jwt.ParseRSAPublicKeyFromPEM([]byte(fmt.Sprintf(
					"-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
					key.X5c[0],
				)))
			}
		}
	}

	return nil, fmt.Errorf("unable to find appropriate key for kid: %s", kid)
}

// ValidateToken validates a JWT token using Keycloak's public keys
func (v *JWTValidator) ValidateToken(ctx context.Context, tokenString string) (*OAuthClaims, error) {
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, v.getSigningKey,
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(keycloakBaseURL),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse/validate token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Extract custom claims
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	// Parse scopes
	var scopes []string
	if claims.Scope != "" {
		scopes = strings.Split(claims.Scope, " ")
	}

	return &OAuthClaims{
		Subject:          claims.Subject,
		Username:         claims.PreferredUsername,
		ClientID:         claims.ClientID,
		Scopes:           scopes,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}

// OAuthMiddleware creates HTTP middleware for OAuth token validation
func OAuthMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Printf("Request from %s missing Authorization header", r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Parse Bearer token
			if !strings.HasPrefix(authHeader, "Bearer ") {
				log.Printf("Request from %s has invalid Authorization format", r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if strings.TrimSpace(tokenString) == "" {
				log.Printf("Request from %s has empty Bearer token", r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Empty token", http.StatusUnauthorized)
				return
			}

			// Validate token
			claims, err := validator.ValidateToken(r.Context(), tokenString)
			if err != nil {
				log.Printf("Token validation failed for request from %s: %v", r.RemoteAddr, err)
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			log.Printf("Authorized request from user: %s (subject: %s, client: %s)",
				claims.Username, claims.Subject, claims.ClientID)

			// Add claims to request context
			ctx := context.WithValue(r.Context(), "oauth_claims", claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// HelloTool implements a simple MCP tool that returns "HO"
func HelloTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get OAuth claims from context
	claims, ok := ctx.Value("oauth_claims").(*OAuthClaims)
	if !ok {
		log.Printf("Warning: OAuth claims not found in context for hello tool")
	} else {
		log.Printf("Hello tool called by user: %s (subject: %s)", claims.Username, claims.Subject)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: "HO",
			},
		},
	}, nil
}

// SetupMCPServer creates and configures the MCP server
func SetupMCPServer() *server.MCPServer {
	// Create MCP server
	s := server.NewMCPServer(
		"oauth-protected-server",
		"1.0.0",
	)

	// Register the hello tool
	s.AddTool(mcp.Tool{
		Name:        "hello",
		Description: "A simple tool that returns 'HO'",
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: map[string]any{},
		},
	}, HelloTool)

	log.Printf("Registered MCP tool: hello")
	return s
}

// SetupOAuthMetadataEndpoint provides OAuth discovery endpoint for the MCP server
func SetupOAuthMetadataEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"authorization_endpoint":   keycloakBaseURL + "/protocol/openid-connect/auth",
			"token_endpoint":           keycloakBaseURL + "/protocol/openid-connect/token",
			"jwks_uri":                 keycloakJWKSURL,
			"issuer":                   keycloakBaseURL,
			"scopes_supported":         []string{"openid", "profile", "email"},
			"response_types_supported": []string{"code"},
			"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
}

func main() {
	log.Printf("Starting OAuth-protected MCP Server...")
	log.Printf("Keycloak Base URL: %s", keycloakBaseURL)
	log.Printf("JWKS URL: %s", keycloakJWKSURL)

	// Create JWT validator
	validator, err := NewJWTValidator()
	if err != nil {
		log.Fatalf("Failed to create JWT validator: %v", err)
	}

	// Create MCP server
	mcpServer := SetupMCPServer()

	// Create HTTP transport for MCP
	httpServer := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithEndpointPath(mcpEndpoint),
	)

	// Setup routes
	mux := http.NewServeMux()

	// OAuth metadata endpoint
	mux.HandleFunc("/.well-known/oauth-protected-resource", SetupOAuthMetadataEndpoint())

	// Protected MCP endpoint with OAuth middleware
	mux.Handle(mcpEndpoint, OAuthMiddleware(validator)(httpServer))

	// Health check endpoint (unprotected)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"server": "oauth-protected-mcp-server",
		})
	})

	// Start server
	log.Printf("Server starting on port %s", serverPort)
	log.Printf("MCP endpoint: %s (OAuth protected)", mcpEndpoint)
	log.Printf("OAuth metadata: /.well-known/oauth-protected-resource")
	log.Printf("Health check: /health")

	if err := http.ListenAndServe(serverPort, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
