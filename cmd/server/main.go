package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/org/secretvault/internal/api"
	"github.com/org/secretvault/internal/storage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type config struct {
	ListenAddr      string `yaml:"listen_addr"`
	TLSCertFile     string `yaml:"tls_cert"`
	TLSKeyFile      string `yaml:"tls_key"`
	DBUrl           string `yaml:"db_url"`
	UnsealThreshold int    `yaml:"unseal_threshold"`
	MigrationsDir   string `yaml:"migrations_dir"`
	LogLevel        string `yaml:"log_level"`
}

func main() {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Load config
	cfgFile := "config.yaml"
	if v := os.Getenv("VAULT_CONFIG"); v != "" {
		cfgFile = v
	}

	cfg := config{
		ListenAddr:      ":8200",
		UnsealThreshold: 3,
		MigrationsDir:   "migrations",
		LogLevel:        "info",
	}

	if data, err := os.ReadFile(cfgFile); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatal().Err(err).Msg("failed to parse config")
		}
	} else {
		log.Warn().Str("file", cfgFile).Msg("config file not found, using defaults")
	}

	// Env overrides
	if v := os.Getenv("VAULT_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DBUrl = v
	}

	// Set log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.DBUrl == "" {
		log.Fatal().Msg("db_url must be configured (or DATABASE_URL env var)")
	}

	ctx := context.Background()

	// Connect to database
	store, err := storage.NewPostgresBackend(ctx, cfg.DBUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer store.Close()

	// Run migrations
	if err := storage.RunMigrations(cfg.DBUrl, cfg.MigrationsDir); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}
	log.Info().Msg("migrations applied")

	// Create server
	srv := api.NewServer(store, api.Config{
		ListenAddr:      cfg.ListenAddr,
		TLSCertFile:     cfg.TLSCertFile,
		TLSKeyFile:      cfg.TLSKeyFile,
		DBUrl:           cfg.DBUrl,
		UnsealThreshold: cfg.UnsealThreshold,
		MigrationsDir:   cfg.MigrationsDir,
	})

	// Auto-unseal if vault is already initialized (reads shards from DB for dev mode)
	initialized, err := store.IsInitialized(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to check init state")
	}
	if !initialized {
		log.Info().Msg("vault not yet initialized - POST /v1/sys/init to initialize")
	} else {
		log.Info().Msg("vault initialized - POST /v1/sys/unseal with key shards to unseal")
	}

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	log.Info().Str("addr", cfg.ListenAddr).Msg("server started")
	<-quit

	log.Info().Msg("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	log.Info().Msg("server stopped")
}
