// Package main is the entry point for the rw3iss Authentication Server
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"time"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/api/routes"
	"github.com/rw3iss/auth/internal/audit"
	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/sso"
	"github.com/rw3iss/auth/internal/background"
	"github.com/rw3iss/auth/internal/cache"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/email"
	"github.com/rw3iss/auth/internal/logging"
	"github.com/rw3iss/auth/internal/repository/postgres"
	"github.com/rw3iss/auth/internal/service"
	auth "github.com/rw3iss/auth/internal/service/auth"
	"github.com/rw3iss/auth/pkg/migration/cognito"
	"github.com/rw3iss/auth/pkg/migration/globalsku"
)

func main() {
	// Load configuration. We use the stdlib log for failures here because
	// the structured logger isn't installed yet — we need the config to
	// know whether to emit JSON or text.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// AUDIT 7.3: install the structured logger as the package-level default
	// before anything else runs. All slog.Info / FromContext calls anywhere
	// downstream route through this handler.
	logger := logging.New(cfg.Server.Environment, getEnvLogLevel(), os.Stdout)
	logging.SetDefault(logger)
	logger.Info("starting auth server", "env", cfg.Server.Environment)

	// Connect to database
	db, err := postgres.NewDB(cfg.Database)
	if err != nil {
		logger.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database connected")

	// Apply any unapplied schema migrations before the rest of boot.
	// Failure here is fatal — a stale schema means routes will return
	// SQL errors at runtime. Idempotent on an up-to-date DB.
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "./migrations"
	}
	migrator := postgres.NewMigrator(db, migrationsDir, logger)
	if err := migrator.Run(context.Background()); err != nil {
		logger.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	// Connect to Redis (graceful fallback to no-op cache)
	redisClient := cache.NewRedisClient(cfg.Redis)
	defer redisClient.Close()
	tokenCache := cache.NewRedisTokenCache(redisClient)

	// AUDIT 1.15: install the trusted-proxy CIDR list before any middleware
	// or handler runs, so X-Forwarded-For parsing is consistently scoped.
	if err := middleware.ConfigureTrustedProxies(cfg.Security.TrustedProxies); err != nil {
		logger.Error("invalid TRUSTED_PROXIES configuration", "err", err)
		os.Exit(1)
	}

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	orgRepo := postgres.NewOrganizationRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	permRepo := postgres.NewPermissionRepository(db)
	inviteRepo := postgres.NewInvitationRepository(db)
	tokenRepo := postgres.NewTokenRepository(db)
	appRepo := postgres.NewAppRepository(db)
	m2mRepo := postgres.NewM2MClientRepository(db)
	txManager := postgres.NewTransactionManager(db)

	// Initialize JWT service with cache
	jwtService := jwt.NewService(cfg.JWT, tokenRepo, tokenCache)

	// Audit writer. Sink is Postgres when audit is enabled, NoOp otherwise
	// so the package-level Record() function is always safe to call. The
	// writer's Enabled flag is set from config; future runtime toggling
	// goes through SetEnabled (exposed via admin endpoint in B5 work).
	var auditSink audit.Sink = audit.NoopSink{}
	if cfg.Audit.Enabled {
		auditSink = audit.NewPostgresSink(db.DB)
	}
	auditWriter := audit.New(audit.Config{
		Enabled:    cfg.Audit.Enabled,
		BufferSize: cfg.Audit.BufferSize,
	}, auditSink)
	audit.SetDefault(auditWriter)
	defer auditWriter.Stop()

	// Background-job scheduler. Cleanup jobs run hourly; intervals can be
	// tuned via env later if anything proves too aggressive. The scheduler
	// is exposed through /admin/jobs (see job_handler.go) so operators can
	// trigger / pause / resume each job at runtime.
	scheduler := background.NewScheduler(30*time.Second, logger)
	scheduler.Register(&background.RefreshTokenCleanup{DB: db.DB, Every: time.Hour})
	scheduler.Register(&background.SessionCleanup{DB: db.DB, Every: time.Hour})
	scheduler.Register(&background.PasswordResetTokenCleanup{DB: db.DB, Every: time.Hour})
	scheduler.Register(&background.EmailVerificationTokenCleanup{DB: db.DB, Every: time.Hour})
	schedCtx, schedCancel := context.WithCancel(context.Background())
	scheduler.Start(schedCtx)
	defer func() {
		schedCancel()
		scheduler.Stop()
	}()

	// AUDIT 1.12: prefer the Redis-backed SSO state store so the OAuth
	// callback can land on any replica. Falls back to in-memory when
	// Redis isn't connected — the same fallback the rest of the service
	// uses.
	var ssoStateStore sso.StateStore
	if redisClient.IsConnected() {
		ssoStateStore = sso.NewRedisStateStore(redisClient.Client())
	} else {
		logger.Warn("redis unavailable; using in-memory SSO state store (single-replica only)")
		ssoStateStore = sso.NewInMemoryStateStore(schedCtx)
	}

	// Initialize SSO manager. AUDIT 1.13: pass the redirect-URL allowlist
	// so /auth/sso/url refuses arbitrary client-supplied URLs.
	ssoManager, err := sso.NewManager(schedCtx, cfg.SSO, ssoStateStore, cfg.SSO.AllowedRedirectURLs)
	if err != nil {
		logger.Warn("sso manager init failed", "err", err)
	}
	// AUDIT C2: when Redis is connected, swap the in-memory auth-code store
	// for the Redis-backed one so the PKCE redeem flow works across replicas
	// (a callback on replica A and an exchange on replica B both see the
	// same record).
	if ssoManager != nil && redisClient.IsConnected() {
		ssoManager.SetAuthCodeStore(sso.NewRedisAuthCodeStore(redisClient.Client()))
	}

	// Initialize email service. Provider is picked by EMAIL_PROVIDER:
	//   - "sendgrid" → native v3 API, locally-rendered HTML
	//   - "smtp"     → generic SMTP (works for SendGrid SMTP, Postmark
	//                  SMTP, raw mailserver, ...)
	//   - anything else / unconfigured → logging NoOp (dev-only;
	//                  reset / verify / magic-link URLs are logged so
	//                  devs can pull them from journalctl)
	//
	// All concrete providers share the same Renderer instance so the
	// rendered HTML is identical across transports.
	emailRenderer := email.NewRenderer(email.RendererConfig{
		BrandName:    cfg.Email.FromName,
		OverrideDir:  cfg.Email.TemplatesPath, // empty = embedded-only
		SupportEmail: cfg.Email.FromAddress,
	})
	var emailService service.EmailService
	switch cfg.Email.Provider {
	case "sendgrid":
		emailService, err = email.NewSendGridService(cfg.Email, emailRenderer, logger)
		if err != nil {
			logger.Warn("sendgrid init failed; falling back to logging no-op", "err", err)
			emailService = email.NewNoOpEmailService(logger)
		} else {
			logger.Info("email provider: sendgrid", "from", cfg.Email.FromAddress)
		}
	case "smtp":
		if cfg.Email.SMTPHost == "" {
			logger.Warn("EMAIL_PROVIDER=smtp but SMTP_HOST not set — using logging no-op")
			emailService = email.NewNoOpEmailService(logger)
		} else {
			emailService, err = email.NewSMTPService(cfg.Email)
			if err != nil {
				logger.Warn("smtp init failed; falling back to logging no-op", "err", err)
				emailService = email.NewNoOpEmailService(logger)
			}
		}
	default:
		logger.Warn("email provider not configured — using logging no-op (suitable for dev only)")
		emailService = email.NewNoOpEmailService(logger)
	}

	// AUDIT B7b: optional legacy-Cognito auto-migrate adapter. When
	// COGNITO_AUTO_MIGRATE_ENABLED is true and pool config is present,
	// instantiate the adapter and inject it into AuthService via the
	// WithLegacyAuth setter. Off by default — deployments that don't need
	// migration get an auth-server that never touches AWS.
	var legacyAuth interface{} = nil
	if cfg.CognitoMigration.Enabled {
		bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
		cognitoAdapter, cerr := cognito.New(bootCtx, cognito.Config{
			Region:       cfg.CognitoMigration.Region,
			UserPoolID:   cfg.CognitoMigration.UserPoolID,
			ClientID:     cfg.CognitoMigration.ClientID,
			ClientSecret: cfg.CognitoMigration.ClientSecret,
		})
		bootCancel()
		if cerr != nil {
			logger.Error("cognito migration adapter init failed; auto-migrate disabled", "err", cerr)
		} else {
			legacyAuth = cognitoAdapter
			logger.Info("cognito auto-migrate enabled",
				"region", cfg.CognitoMigration.Region,
				"pool", cfg.CognitoMigration.UserPoolID,
			)
		}
	}

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

	// If the Cognito adapter initialised cleanly, inject it. The setter
	// is no-op when called with nil so the path stays uniform.
	if adapter, ok := legacyAuth.(*cognito.Adapter); ok && adapter != nil {
		authService.WithLegacyAuth(adapter, nil)
	}

	// GlobalSKU JIT legacy-migration adapter (§5.1). Registered per-app under
	// "globalsku" so the JIT path fires only for logins resolved to that app;
	// every other app is unaffected. Off unless GLOBALSKU_LEGACY_MIGRATION_ENABLED.
	if cfg.GlobalSkuMigration.Enabled {
		gsk, gerr := globalsku.New(globalsku.Config{
			BaseURL:      cfg.GlobalSkuMigration.BaseURL,
			VerifySecret: cfg.GlobalSkuMigration.VerifySecret,
		})
		if gerr != nil {
			logger.Error("globalsku migration adapter init failed; JIT disabled for globalsku", "err", gerr)
		} else {
			authService.WithLegacyAuthFor("globalsku", gsk, nil)
			logger.Info("globalsku legacy JIT migration enabled", "base_url", cfg.GlobalSkuMigration.BaseURL)
		}
	}

	// App-scoping service. AuthService consults this on every Login to
	// resolve app_code → app + check user_apps membership (AUDIT 8.3).
	appService := service.NewAppService(appRepo).WithOrgRepo(orgRepo).WithRoleRepo(roleRepo)
	authService.WithAppService(appService)

	// M2M client_credentials service — backs POST /oauth/token. Closes
	// the AUTH_REGISTRATION_TOKEN shim by giving services rotatable
	// credentials in place of pre-issued long-lived JWTs.
	m2mService := service.NewM2MService(m2mRepo, jwtService, cfg.Security.BcryptCost, slog.Default())

	// Magic-link sign-in service — issues one-tap login links emailed
	// to the user. Mirrors AuthService.Login on the verify side.
	magicLinkService := auth.NewMagicLinkService(
		db.DB, userRepo, roleRepo, tokenRepo, jwtService, emailService, appService,
	)

	// Audit-log read service — backs GET /admin/audit-log.
	auditQueryService := service.NewAuditQueryService(db.DB)

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

	// Setup routes. AUDIT 5.6: pass the scheduler's shutdown context so
	// rate-limiter cleanup goroutines exit cleanly on process shutdown.
	handler := routes.SetupRoutes(
		schedCtx,
		cfg,
		authService,
		userService,
		orgService,
		roleService,
		appService,
		m2mService,
		magicLinkService,
		auditQueryService,
		permRepo,
		jwtService,
		scheduler,
		redisClient,
		tokenCache,
	)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("server listening", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server start failed", "err", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("shutdown signal received")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "err", err)
		os.Exit(1)
	}

	logger.Info("server exited gracefully")
}

// getEnvLogLevel returns the LOG_LEVEL env value or "info" default. Read
// directly to avoid threading a log-level field through every config
// struct just for boot-time use.
func getEnvLogLevel() string {
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		return v
	}
	return "info"
}
