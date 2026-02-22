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
		status, latencyMs, exitIP, region, isp := checkProxyFromNode(ctx, a.Proxy)
		reports = append(reports, types.MappingStatusReport{
			MappingID:   a.MappingID,
			ProxyID:     a.Proxy.ID,
			State:       "APPLIED",
			ProxyStatus: string(status),
			LatencyMs:   latencyMs,
			ExitIP:      exitIP,
			Region:      region,
			ISP:         isp,
		})
	}
	return reports
}

// checkProxyFromNode measures TCP latency to the proxy from this node VPS.
// Returns (status, latencyMs, exitIP, region, isp).
func checkProxyFromNode(ctx context.Context, p types.Proxy) (types.ProxyStatus, int, string, string, string) {
	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	elapsed := int(time.Since(start).Milliseconds())
	if err != nil {
		return types.StatusDown, 0, "", "", ""
	}
	conn.Close()

	// Try to get exit IP + region/ISP via proxy (best-effort)
	exitIP, region, isp := fetchExitInfo(ctx, p)

	var status types.ProxyStatus
	switch {
	case elapsed < 500:
		status = types.StatusOK
	default:
		status = types.StatusDown
	}
	return status, elapsed, exitIP, region, isp
}

// fetchExitInfo fetches exit IP, region, and ISP through the proxy using ip-api.com (plain HTTP).
// Using HTTP (not HTTPS) so the proxy can handle it without needing a CONNECT tunnel.
func fetchExitInfo(ctx context.Context, p types.Proxy) (exitIP, region, isp string) {
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
	}
	if p.Username != nil && p.Password != nil {
		proxyURL.User = url.UserPassword(*p.Username, *p.Password)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}

	// Step 1: Get exit IP via plain HTTP endpoint
	ipEndpoints := []string{
		"http://api.ipify.org?format=text",
		"http://ifconfig.me/ip",
		"http://icanhazip.com/",
	}
	for _, ep := range ipEndpoints {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ep, nil)
		if err != nil { cancel(); continue }
		req.Header.Set("User-Agent", "pgw-node-check/1.0")
		resp, err := client.Do(req)
		cancel()
		if err != nil { continue }
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			exitIP = strings.TrimSpace(string(body))
			if exitIP != "" { break }
		}
	}
	if exitIP == "" { return }

	// Step 2: Geo lookup via ip-api.com (plain HTTP, no proxy needed — master does this directly)
	geoCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	geoReq, err := http.NewRequestWithContext(geoCtx, http.MethodGet,
		"http://ip-api.com/json/"+exitIP+"?fields=country,countryCode,regionName,isp", nil)
	if err != nil { return }
	geoReq.Header.Set("User-Agent", "pgw-node-geo/1.0")
	geoResp, err := http.DefaultClient.Do(geoReq)
	if err != nil { return }
	defer geoResp.Body.Close()
	var geo struct {
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(io.LimitReader(geoResp.Body, 4096)).Decode(&geo); err != nil { return }
	if geo.CountryCode != "" {
		flag := countryCodeToFlag(geo.CountryCode)
		if geo.RegionName != "" && geo.RegionName != geo.Country {
			region = flag + " " + geo.RegionName
		} else if geo.Country != "" {
			region = flag + " " + geo.Country
		} else {
			region = flag
		}
	} else if geo.Country != "" {
		region = geo.Country
	}
	isp = geo.ISP
	return
}

// countryCodeToFlag converts an ISO 3166-1 alpha-2 country code to a flag emoji.
func countryCodeToFlag(code string) string {
	if len(code) != 2 { return "" }
	code = strings.ToUpper(code)
	r1 := rune(0x1F1E6 + int(code[0]-'A'))
	r2 := rune(0x1F1E6 + int(code[1]-'A'))
	return string([]rune{r1, r2})
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
