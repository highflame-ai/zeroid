// Package zeroid provides the core server and configuration for ZeroID —
// the identity layer for autonomous agents and non-human workloads.
// Three-layer config loading: defaults -> YAML file -> environment variable overlays.
package zeroid

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds the complete ZeroID service configuration.
type Config struct {
	Server    ServerConfig    `koanf:"server"`
	Database  DatabaseConfig  `koanf:"database"`
	Keys      KeysConfig      `koanf:"keys"`
	Token     TokenConfig     `koanf:"token"`
	Telemetry TelemetryConfig `koanf:"telemetry"`
	Logging   LoggingConfig   `koanf:"logging"`

	// WIMSEDomain is the domain prefix for SPIFFE/WIMSE URIs (e.g. "zeroid.dev").
	WIMSEDomain string `koanf:"wimse_domain"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port                   string `koanf:"port"`
	Env                    string `koanf:"env"`
	ReadTimeout            string `koanf:"read_timeout"`
	WriteTimeout           string `koanf:"write_timeout"`
	IdleTimeout            string `koanf:"idle_timeout"`
	ShutdownTimeoutSeconds int    `koanf:"shutdown_timeout_seconds"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL          string `koanf:"url"`
	Host         string `koanf:"host"`
	Port         string `koanf:"port"`
	User         string `koanf:"user"`
	Password     string `koanf:"password"`
	Name         string `koanf:"name"`
	SSLMode      string `koanf:"ssl_mode"`
	MaxOpenConns int    `koanf:"max_open_conns"`
	MaxIdleConns int    `koanf:"max_idle_conns"`
	// AutoMigrate controls whether NewServer runs embedded migrations on startup.
	// Default: true (convenient for standalone/dev). Set to false when the deployer
	// manages schema migrations via their own pipeline (production recommended).
	AutoMigrate *bool `koanf:"auto_migrate"`
}

// KeysConfig holds key paths for JWT signing.
// ECDSA P-256 keys are used for NHI/agent flows (ES256).
// RSA keys are used for human/SDK flows (RS256).
type KeysConfig struct {
	PrivateKeyPath string `koanf:"private_key_path"`
	PublicKeyPath  string `koanf:"public_key_path"`
	KeyID          string `koanf:"key_id"`
	// RSA key paths for RS256 signing (human/SDK tokens).
	RSAPrivateKeyPath string `koanf:"rsa_private_key_path"`
	RSAPublicKeyPath  string `koanf:"rsa_public_key_path"`
	RSAKeyID          string `koanf:"rsa_key_id"`
}

// TokenConfig holds JWT issuance settings.
type TokenConfig struct {
	Issuer     string `koanf:"issuer"`
	BaseURL    string `koanf:"base_url"`
	DefaultTTL int    `koanf:"default_ttl"`
	MaxTTL     int    `koanf:"max_ttl"`

	// authorization_code grant configuration.
	// HMACSecret is the shared secret used to sign and verify auth code JWTs (HS256).
	HMACSecret string `koanf:"hmac_secret"`
	// AuthCodeIssuer is the expected issuer claim in auth code JWTs.
	// Defaults to Token.Issuer when empty.
	AuthCodeIssuer string `koanf:"auth_code_issuer"`
}

// TelemetryConfig holds OpenTelemetry settings.
type TelemetryConfig struct {
	Enabled      bool    `koanf:"enabled"`
	Endpoint     string  `koanf:"endpoint"`
	Insecure     bool    `koanf:"insecure"`
	ServiceName  string  `koanf:"service_name"`
	SamplingRate float64 `koanf:"sampling_rate"`
}

// LoggingConfig holds structured logging settings.
type LoggingConfig struct {
	Level string `koanf:"level"`
}

// LoadConfig reads configuration using Koanf: defaults -> YAML file -> environment overlays.
func LoadConfig(configPath string) (Config, error) {
	k := koanf.New(".")

	if err := loadDefaults(k); err != nil {
		return Config{}, fmt.Errorf("loading defaults: %w", err)
	}

	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("loading config file %s: %w", configPath, err)
		}
	}

	if err := loadEnvVars(k); err != nil {
		return Config{}, fmt.Errorf("loading env vars: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Build database URL from individual vars if not provided directly.
	if cfg.Database.URL == "" && cfg.Database.Host != "" {
		cfg.Database.URL = buildDatabaseURL(&cfg.Database)
	}

	return cfg, nil
}

// Validate checks required fields and value ranges.
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return fmt.Errorf("server.port is required")
	}
	if c.Database.URL == "" {
		return fmt.Errorf("database URL is required: provide ZEROID_DATABASE_URL or individual DB_ vars")
	}
	if c.Keys.PrivateKeyPath == "" {
		return fmt.Errorf("keys.private_key_path is required")
	}
	if _, err := os.Stat(c.Keys.PrivateKeyPath); err != nil {
		return fmt.Errorf("private key not found at %s (run 'make setup-keys'): %w", c.Keys.PrivateKeyPath, err)
	}
	if c.Keys.PublicKeyPath == "" {
		return fmt.Errorf("keys.public_key_path is required")
	}
	if _, err := os.Stat(c.Keys.PublicKeyPath); err != nil {
		return fmt.Errorf("public key not found at %s (run 'make setup-keys'): %w", c.Keys.PublicKeyPath, err)
	}
	if c.Database.MaxOpenConns <= 0 {
		return fmt.Errorf("database.max_open_conns must be > 0, got %d", c.Database.MaxOpenConns)
	}
	if c.Database.MaxIdleConns < 0 || c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("database.max_idle_conns must be between 0 and max_open_conns, got %d", c.Database.MaxIdleConns)
	}
	return nil
}

func loadDefaults(k *koanf.Koanf) error {
	defaults := map[string]any{
		// Server
		"server.port":                    "8899",
		"server.env":                     "development",
		"server.read_timeout":            "15s",
		"server.write_timeout":           "15s",
		"server.idle_timeout":            "60s",
		"server.shutdown_timeout_seconds": 30,

		// Database
		"database.port":           "5432",
		"database.ssl_mode":       "disable",
		"database.max_open_conns": 25,
		"database.max_idle_conns": 5,

		// Keys
		"keys.private_key_path":     "./keys/private.pem",
		"keys.public_key_path":      "./keys/public.pem",
		"keys.key_id":               "zeroid-key-1",
		"keys.rsa_private_key_path": "",
		"keys.rsa_public_key_path":  "",
		"keys.rsa_key_id":           "v1",

		// Token
		"token.issuer":      "https://highflame.ai",
		"token.base_url":    "https://highflame.ai",
		"token.default_ttl": 3600,
		"token.max_ttl":     7776000, // 90 days

		// WIMSE
		"wimse_domain": "highflame.ai",

		// Telemetry
		"telemetry.enabled":       false,
		"telemetry.endpoint":      "localhost:4317",
		"telemetry.insecure":      true,
		"telemetry.service_name":  "zeroid",
		"telemetry.sampling_rate": 1.0,

		// Logging
		"logging.level": "info",
	}

	for key, val := range defaults {
		if err := k.Set(key, val); err != nil {
			return fmt.Errorf("setting default %s: %w", key, err)
		}
	}
	return nil
}

func loadEnvVars(k *koanf.Koanf) error {
	envMapping := map[string]string{
		// Server
		"ZEROID_PORT": "server.port",
		"ZEROID_ENV":  "server.env",

		// Database
		"ZEROID_DATABASE_URL": "database.url",
		"DB_HOST":             "database.host",
		"DB_PORT":             "database.port",
		"DB_USERNAME":         "database.user",
		"DB_PASSWORD":         "database.password",
		"ZEROID_DB_NAME":      "database.name",
		"DB_SSL_MODE":             "database.ssl_mode",
		"ZEROID_AUTO_MIGRATE":     "database.auto_migrate",

		// Keys
		"ZEROID_PRIVATE_KEY_PATH":     "keys.private_key_path",
		"ZEROID_PUBLIC_KEY_PATH":      "keys.public_key_path",
		"ZEROID_KEY_ID":               "keys.key_id",
		"ZEROID_RSA_PRIVATE_KEY_PATH": "keys.rsa_private_key_path",
		"ZEROID_RSA_PUBLIC_KEY_PATH":  "keys.rsa_public_key_path",
		"ZEROID_RSA_KEY_ID":           "keys.rsa_key_id",

		// Token
		"ZEROID_ISSUER":                "token.issuer",
		"ZEROID_BASE_URL":              "token.base_url",
		"ZEROID_TOKEN_TTL_SECONDS":     "token.default_ttl",
		"ZEROID_MAX_TOKEN_TTL_SECONDS": "token.max_ttl",

		// WIMSE
		"ZEROID_WIMSE_DOMAIN": "wimse_domain",

		// Telemetry
		"OTEL_EXPORTER_OTLP_ENDPOINT": "telemetry.endpoint",
		"OTEL_ENABLED":                "telemetry.enabled",
		"OTEL_INSECURE":               "telemetry.insecure",

		// Logging
		"ZEROID_LOG_LEVEL": "logging.level",
	}

	for envVar, configPath := range envMapping {
		value := os.Getenv(envVar)
		if value == "" {
			continue
		}

		switch {
		case strings.HasSuffix(configPath, ".enabled") || strings.HasSuffix(configPath, ".insecure"):
			if boolVal, err := strconv.ParseBool(value); err == nil {
				_ = k.Set(configPath, boolVal)
			}
		case strings.HasSuffix(configPath, ".max_open_conns") ||
			strings.HasSuffix(configPath, ".max_idle_conns") ||
			strings.HasSuffix(configPath, ".default_ttl") ||
			strings.HasSuffix(configPath, ".max_ttl") ||
			strings.HasSuffix(configPath, ".shutdown_timeout_seconds"):
			if intVal, err := strconv.Atoi(value); err == nil {
				_ = k.Set(configPath, intVal)
			}
		case strings.HasSuffix(configPath, ".sampling_rate"):
			if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
				_ = k.Set(configPath, floatVal)
			}
		default:
			_ = k.Set(configPath, value)
		}
	}

	return nil
}

func buildDatabaseURL(db *DatabaseConfig) string {
	userInfo := db.User
	if db.Password != "" {
		userInfo += ":" + db.Password
	}
	url := fmt.Sprintf("postgres://%s@%s:%s/%s", userInfo, db.Host, db.Port, db.Name)
	if db.SSLMode != "" {
		url += "?sslmode=" + db.SSLMode
	}
	return url
}
