// internal/config/config.go — pgw-node configuration loader.
package config

import (
	"os"
	"time"
)

type Config struct {
	ServerURL    string
	NodeID       string
	KeyPath      string
	PollInterval time.Duration
	AgentURL     string // local pgw-agent API (default: http://127.0.0.1:9090)
}

func Load() *Config {
	c := &Config{
		ServerURL:    getEnv("PGW_SERVER", "http://127.0.0.1:8080"),
		NodeID:       getEnv("PGW_NODE_ID", ""),
		KeyPath:      getEnv("PGW_KEY_PATH", "/etc/pgw-node/node.key"),
		AgentURL:     getEnv("PGW_AGENT_URL", "http://127.0.0.1:9090"),
		PollInterval: parseDuration(getEnv("PGW_POLL_INTERVAL", "15s"), 15*time.Second),
	}
	return c
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return fallback
}
