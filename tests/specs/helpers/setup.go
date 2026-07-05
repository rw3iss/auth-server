//go:build integration

package helpers

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rw3iss/auth/internal/api/routes"
	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/sso"
	"github.com/rw3iss/auth/internal/cache"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/email"
	"github.com/rw3iss/auth/internal/repository/postgres"
	"github.com/rw3iss/auth/internal/service"
	auth "github.com/rw3iss/auth/internal/service/auth"
)

// loadEnvFile loads KEY=VALUE pairs from a file into the process environment.
// Variables that are already set in the environment are left unchanged, so
// explicit exports (e.g. from run-tests.sh) always take priority.
// Missing files are silently ignored.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // file absent — not an error
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		// Only set if not already set (explicit env wins)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}

// findProjectRoot walks up the directory tree from the current working
// directory until it finds a directory containing go.mod.
func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func init() {
	// Auto-load .env.test from the project root so tests can be run without
	// manually exporting env vars (e.g. via make test-cli or go test directly).
	if root := findProjectRoot(); root != "" {
		loadEnvFile(filepath.Join(root, ".env.test"))
	}
}

// TestEnvironment holds all services needed for integration tests
type TestEnvironment struct {
	Server      *httptest.Server
	Config      *config.Config
	DB          *postgres.DB
	RedisClient *cache.RedisClient
	Client      *TestClient
}

// NewTestEnvironment creates a full test environment with HTTP test server
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	t.Helper()

	// Load configuration from environment
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Connect to test database
	db, err := postgres.NewDB(cfg.Database)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations
	runMigrations(t, cfg)

	// Connect to Redis
	redisClient := cache.NewRedisClient(cfg.Redis)
	tokenCache := cache.NewRedisTokenCache(redisClient)

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	orgRepo := postgres.NewOrganizationRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	inviteRepo := postgres.NewInvitationRepository(db)
	tokenRepo := postgres.NewTokenRepository(db)
	txManager := postgres.NewTransactionManager(db)

	// Initialize JWT service with cache
	jwtService := jwt.NewService(cfg.JWT, tokenRepo, tokenCache)

	// Initialize SSO manager (no-op for tests). Empty allowedRedirects
	// disables the AUDIT 1.13 gate — tests don't exercise SSO redirects.
	// context.Background is fine — the test cleanup tears down the
	// in-memory stores before the process exits.
	ssoManager, _ := sso.NewManager(context.Background(), cfg.SSO, nil, nil)

	// Initialize email service (no-op)
	emailService := email.NewNoOpEmailService()

	// Initialize services
	authService := auth.NewAuthService(
		cfg,
		userRepo,
		orgRepo,
		roleRepo,
		permRepo,
		inviteRepo,
		tokenRepo,
		txManager,
		jwtService,
		ssoManager,
		emailService,
		tokenCache,
	)

	userService := service.NewUserService(
		userRepo,
		orgRepo,
		roleRepo,
		txManager,
	)

	orgService := service.NewOrganizationService(
		cfg,
		orgRepo,
		userRepo,
		roleRepo,
		inviteRepo,
		txManager,
		emailService,
	)

	roleService := service.NewRoleService(
		roleRepo,
		permRepo,
		orgRepo,
	)

	// Setup routes. SetupRoutes signature is
	// (ctx, cfg, auth, user, org, role, app, permRepo, jwt, scheduler, redis, tokenCache?).
	// Tests don't exercise the background scheduler so we pass nil — the
	// JobHandler is tolerant of that (List returns an empty array, etc.).
	// ctx = t-scoped Background; the rate-limiter cleanup goroutine
	// terminates with the test process (and the cancel is called in
	// env.Cleanup).
	routeCtx, routeCancel := context.WithCancel(context.Background())
	t.Cleanup(routeCancel)
	handler := routes.SetupRoutes(
		routeCtx,
		cfg,
		authService,
		userService,
		orgService,
		roleService,
		nil, // appService — tests don't exercise app scoping; AllowBaseUserLogin is implicit
		permRepo,
		jwtService,
		nil, // scheduler
		redisClient,
		tokenCache,
	)

	// Flush rate limit keys from Redis to ensure clean state for tests
	if redisClient.IsConnected() {
		ctx := context.Background()
		// Delete known rate limit keys (test client always uses 127.0.0.1)
		redisClient.Client().Del(ctx, "auth:ratelimit:127.0.0.1")
	}

	// Create test server
	server := httptest.NewServer(handler)

	env := &TestEnvironment{
		Server:      server,
		Config:      cfg,
		DB:          db,
		RedisClient: redisClient,
		Client:      NewTestClient(server.URL, cfg.Server.APIPrefix),
	}

	t.Cleanup(func() {
		env.Cleanup()
	})

	return env
}

// Cleanup shuts down the test environment
func (env *TestEnvironment) Cleanup() {
	if env.Server != nil {
		env.Server.Close()
	}
	if env.RedisClient != nil {
		env.RedisClient.Close()
	}
	if env.DB != nil {
		env.DB.Close()
	}
}

// CleanDatabase removes all test data
func (env *TestEnvironment) CleanDatabase(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	tables := []string{
		"sessions",
		"refresh_tokens",
		"password_reset_tokens",
		"email_verification_tokens",
		"organization_member_roles",
		"organization_members",
		"user_base_roles",
		"user_auth_providers",
		"invitation_roles",
		"invitations",
		"role_permissions",
		"audit_log",
	}

	for _, table := range tables {
		_, err := env.DB.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			t.Logf("Warning: failed to clean table %s: %v", table, err)
		}
	}

	// Clean users (except seed data)
	_, _ = env.DB.ExecContext(ctx, "DELETE FROM users WHERE email NOT LIKE '%@seed.test'")
}

func runMigrations(t *testing.T, cfg *config.Config) {
	t.Helper()

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "./migrations"
	}

	// Migrations are applied via docker-entrypoint-initdb.d in the compose setup
	// For direct test runs, they should already be applied
	log.Println("Using pre-applied migrations from Docker setup")
}
