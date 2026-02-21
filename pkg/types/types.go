// pkg/types/types.go — shared types matching master server API contracts.
package types

import "time"

type ProxyStatus string

const (
	StatusOK   ProxyStatus = "OK"
	StatusDown ProxyStatus = "DOWN"
)

type Proxy struct {
	ID        string      `json:"id"`
	Label     string      `json:"label,omitempty"`
	Type      string      `json:"type"`
	Host      string      `json:"host"`
	Port      int         `json:"port"`
	Username  *string     `json:"username,omitempty"`
	Password  *string     `json:"password,omitempty"`
	Enabled   bool        `json:"enabled"`
	Status    ProxyStatus `json:"status"`
	LatencyMs *int        `json:"latency_ms,omitempty"`
	ExitIP    *string     `json:"exit_ip,omitempty"`
}

type NodeAssignment struct {
	NodeID      string             `json:"node_id"`
	Assignments []ProxyMappingPair `json:"assignments"`
}

type ProxyMappingPair struct {
	MappingID  string `json:"mapping_id"`
	ClientCIDR string `json:"client_cidr"`
	LocalPort  int    `json:"local_port"`
	Proxy      Proxy  `json:"proxy"`
}

type NodeHeartbeat struct {
	Version  string                `json:"version"`
	Mappings []MappingStatusReport `json:"mappings"`
}

type MappingStatusReport struct {
	MappingID   string `json:"mapping_id"`
	State       string `json:"state"`
	ProxyStatus string `json:"proxy_status"`
	LatencyMs   int    `json:"latency_ms"`
	ExitIP      string `json:"exit_ip"`
}

// TimePtr is a helper to get the time pointer
type TimePtr = *time.Time
