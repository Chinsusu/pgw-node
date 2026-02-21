// internal/sync/sync.go — core sync loop for pgw-node.
// Polls master server for assignments and reports heartbeat.
package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/pgw-node/internal/config"
	"github.com/Chinsusu/pgw-node/internal/keypair"
	"github.com/Chinsusu/pgw-node/pkg/types"
)

// Syncer polls the master for assignments and reports heartbeat.
type Syncer struct {
	cfg     *config.Config
	kp      *keypair.KeyPair
	version string
	client  *http.Client
}

func New(cfg *config.Config, kp *keypair.KeyPair, version string) *Syncer {
	return &Syncer{
		cfg:     cfg,
		kp:      kp,
		version: version,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Run starts the sync loop; blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.PollInterval)
	defer tick.Stop()

	// Run once immediately
	s.syncOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.syncOnce(ctx)
		}
	}
}

func (s *Syncer) syncOnce(ctx context.Context) {
	assignments, err := s.fetchAssignments(ctx)
	if err != nil {
		fmt.Printf("[sync] fetch assignments error: %v\n", err)
		return
	}

	// Apply mappings locally via pgw-agent
	reports := s.reconcileLocal(ctx, assignments)

	// Send heartbeat
	if err := s.sendHeartbeat(ctx, reports); err != nil {
		fmt.Printf("[sync] heartbeat error: %v\n", err)
	}
}

func (s *Syncer) fetchAssignments(ctx context.Context) (*types.NodeAssignment, error) {
	url := fmt.Sprintf("%s/v1/nodes/%s/assignments", s.cfg.ServerURL, s.cfg.NodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	s.signRequest(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var a types.NodeAssignment
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &a, nil
}

func (s *Syncer) reconcileLocal(ctx context.Context, assignments *types.NodeAssignment) []types.MappingStatusReport {
	// Tell local pgw-agent to reconcile (apply nft rules)
	_, _ = s.client.Get(s.cfg.AgentURL + "/agent/reconcile")

	// Check each proxy from this node and build status reports
	var reports []types.MappingStatusReport
	for _, a := range assignments.Assignments {
		status, latencyMs, exitIP := checkProxyFromNode(ctx, a.Proxy)
		reports = append(reports, types.MappingStatusReport{
			MappingID:   a.MappingID,
			ProxyID:     a.Proxy.ID,
			State:       "APPLIED",
			ProxyStatus: string(status),
			LatencyMs:   latencyMs,
			ExitIP:      exitIP,
		})
	}
	return reports
}

// checkProxyFromNode measures TCP latency to the proxy from this node VPS.
// Returns (status, latencyMs, exitIP).
func checkProxyFromNode(ctx context.Context, p types.Proxy) (types.ProxyStatus, int, string) {
	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	elapsed := int(time.Since(start).Milliseconds())
	if err != nil {
		return types.StatusDown, 0, ""
	}
	conn.Close()

	// Try to get exit IP via HTTP CONNECT through proxy (best-effort)
	exitIP := fetchExitIPHTTP(ctx, p)

	var status types.ProxyStatus
	switch {
	case elapsed < 500:
		status = types.StatusOK
	default:
		status = types.StatusDown
	}
	return status, elapsed, exitIP
}

// fetchExitIPHTTP fetches the exit IP of the proxy via a HTTP request through it.
func fetchExitIPHTTP(ctx context.Context, p types.Proxy) string {
	proxyURL := fmt.Sprintf("http://%s:%d", p.Host, p.Port)
	if p.Username != nil && p.Password != nil {
		proxyURL = fmt.Sprintf("http://%s:%s@%s:%d", *p.Username, *p.Password, p.Host, p.Port)
	}
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func (s *Syncer) sendHeartbeat(ctx context.Context, reports []types.MappingStatusReport) error {
	hb := types.NodeHeartbeat{
		Version:  s.version,
		Mappings: reports,
	}
	body, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/nodes/%s/heartbeat", s.cfg.ServerURL, s.cfg.NodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.signRequest(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// signRequest adds Ed25519 auth headers to the request.
func (s *Syncer) signRequest(req *http.Request) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := s.cfg.NodeID + ":" + ts
	sig := s.kp.Sign([]byte(message))
	req.Header.Set("X-Node-ID", s.cfg.NodeID)
	req.Header.Set("X-Node-TS", ts)
	req.Header.Set("X-Node-Sig", sig)
}
