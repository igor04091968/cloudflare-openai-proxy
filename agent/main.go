package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WorkerURL                string            `yaml:"worker_url"`
	AgentToken               string            `yaml:"agent_token"`
	ProjectSlug              string            `yaml:"project_slug"`
	Node                     NodeConfig        `yaml:"node"`
	HeartbeatSec             int               `yaml:"heartbeat_sec"`
	PullActionsSec           int               `yaml:"pull_actions_sec"`
	LeaseSec                 int               `yaml:"lease_sec"`
	Checks                   []CheckConfig     `yaml:"checks"`
	AllowedServices          []string          `yaml:"allowed_services"`
	UpstreamProfiles         map[string]string `yaml:"upstream_profiles"`
	ActiveUpstreamPath       string            `yaml:"active_upstream_path"`
	ReloadServiceAfterSwitch string            `yaml:"reload_service_after_switch"`
	DrainFilePath            string            `yaml:"drain_file_path"`
}

type NodeConfig struct {
	Slug     string `yaml:"slug"`
	Name     string `yaml:"name"`
	Hostname string `yaml:"hostname"`
	Region   string `yaml:"region"`
}

type CheckConfig struct {
	Slug      string `yaml:"slug"`
	Name      string `yaml:"name"`
	Protocol  string `yaml:"protocol"`
	Target    string `yaml:"target"`
	TimeoutMS int    `yaml:"timeout_ms"`
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

type heartbeatRequest struct {
	ProjectSlug string                 `json:"projectSlug"`
	Status      string                 `json:"status"`
	Node        nodePayload            `json:"node"`
	Checks      []heartbeatCheckResult `json:"checks"`
}

type nodePayload struct {
	Slug     string         `json:"slug"`
	Name     string         `json:"name"`
	Hostname string         `json:"hostname"`
	Region   string         `json:"region"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type heartbeatCheckResult struct {
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latencyMs,omitempty"`
	Error     string `json:"error,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

type pullActionsRequest struct {
	ProjectSlug string `json:"projectSlug"`
	NodeSlug    string `json:"nodeSlug"`
	Limit       int    `json:"limit"`
	LeaseSec    int    `json:"leaseSec"`
}

type pullActionsEnvelope struct {
	OK      bool `json:"ok"`
	Actions []struct {
		ID          string         `json:"id"`
		RunbookSlug string         `json:"runbookSlug"`
		ActionType  string         `json:"actionType"`
		Params      map[string]any `json:"params"`
		LeaseToken  string         `json:"leaseToken"`
	} `json:"actions"`
}

type actionResultRequest struct {
	LeaseToken string         `json:"leaseToken"`
	Status     string         `json:"status"`
	Summary    string         `json:"summary,omitempty"`
	Result     map[string]any `json:"result,omitempty"`
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to agent config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	agent := newClient(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("vds-proxy-agent started for node=%s project=%s", cfg.Node.Slug, cfg.ProjectSlug)

	heartbeatTicker := time.NewTicker(time.Duration(cfg.HeartbeatSec) * time.Second)
	defer heartbeatTicker.Stop()
	actionsTicker := time.NewTicker(time.Duration(cfg.PullActionsSec) * time.Second)
	defer actionsTicker.Stop()

	if err := agent.sendHeartbeat(ctx); err != nil {
		log.Printf("initial heartbeat failed: %v", err)
	}
	if err := agent.pullAndExecute(ctx); err != nil {
		log.Printf("initial action pull failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Print("agent stopped")
			return
		case <-heartbeatTicker.C:
			if err := agent.sendHeartbeat(ctx); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}
		case <-actionsTicker.C:
			if err := agent.pullAndExecute(ctx); err != nil {
				log.Printf("pull actions failed: %v", err)
			}
		}
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	if cfg.WorkerURL == "" || cfg.AgentToken == "" || cfg.ProjectSlug == "" {
		return cfg, errors.New("worker_url, agent_token, and project_slug are required")
	}
	if cfg.Node.Slug == "" {
		return cfg, errors.New("node.slug is required")
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 30
	}
	if cfg.PullActionsSec <= 0 {
		cfg.PullActionsSec = 10
	}
	if cfg.LeaseSec <= 0 {
		cfg.LeaseSec = 120
	}
	return cfg, nil
}

func newClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) sendHeartbeat(ctx context.Context) error {
	results := make([]heartbeatCheckResult, 0, len(c.cfg.Checks))
	overall := "healthy"
	for _, check := range c.cfg.Checks {
		result := c.runCheck(ctx, check)
		if result.Status != "pass" {
			overall = "degraded"
		}
		results = append(results, result)
	}

	payload := heartbeatRequest{
		ProjectSlug: c.cfg.ProjectSlug,
		Status:      overall,
		Node: nodePayload{
			Slug:     c.cfg.Node.Slug,
			Name:     c.cfg.Node.Name,
			Hostname: c.cfg.Node.Hostname,
			Region:   c.cfg.Node.Region,
		},
		Checks: results,
	}

	return c.postJSON(ctx, "/v1/agent/heartbeat", payload, nil)
}

func (c *Client) pullAndExecute(ctx context.Context) error {
	var envelope pullActionsEnvelope
	err := c.postJSON(ctx, "/v1/agent/pull-actions", pullActionsRequest{
		ProjectSlug: c.cfg.ProjectSlug,
		NodeSlug:    c.cfg.Node.Slug,
		Limit:       1,
		LeaseSec:    c.cfg.LeaseSec,
	}, &envelope)
	if err != nil {
		return err
	}

	for _, action := range envelope.Actions {
		if err := c.executeAction(ctx, action); err != nil {
			log.Printf("action %s failed: %v", action.ID, err)
		}
	}
	return nil
}

func (c *Client) executeAction(ctx context.Context, action struct {
	ID          string         `json:"id"`
	RunbookSlug string         `json:"runbookSlug"`
	ActionType  string         `json:"actionType"`
	Params      map[string]any `json:"params"`
	LeaseToken  string         `json:"leaseToken"`
}) error {
	startReq := actionResultRequest{
		LeaseToken: action.LeaseToken,
		Status:     "running",
		Summary:    fmt.Sprintf("starting %s", action.ActionType),
	}
	if err := c.postJSON(ctx, "/v1/agent/actions/"+action.ID+"/result", startReq, nil); err != nil {
		return fmt.Errorf("mark running: %w", err)
	}

	result, err := c.runAllowlistedAction(ctx, action.ActionType, action.Params)
	req := actionResultRequest{
		LeaseToken: action.LeaseToken,
		Result:     result,
	}
	if err != nil {
		req.Status = "failed"
		req.Summary = err.Error()
	} else {
		req.Status = "succeeded"
		req.Summary = "action completed"
	}

	postErr := c.postJSON(ctx, "/v1/agent/actions/"+action.ID+"/result", req, nil)
	if postErr != nil {
		return fmt.Errorf("submit result: %w", postErr)
	}
	return err
}

func (c *Client) runAllowlistedAction(ctx context.Context, actionType string, params map[string]any) (map[string]any, error) {
	switch actionType {
	case "restart_service":
		service, err := c.allowedService(params["service"])
		if err != nil {
			return nil, err
		}
		return c.runCommand(ctx, "systemctl", "restart", service)
	case "reload_service":
		service, err := c.allowedService(params["service"])
		if err != nil {
			return nil, err
		}
		return c.runCommand(ctx, "systemctl", "reload", service)
	case "switch_upstream":
		profile, _ := params["profile"].(string)
		if profile == "" {
			return nil, errors.New("switch_upstream requires params.profile")
		}
		source, ok := c.cfg.UpstreamProfiles[profile]
		if !ok {
			return nil, fmt.Errorf("unknown upstream profile: %s", profile)
		}
		if c.cfg.ActiveUpstreamPath == "" {
			return nil, errors.New("active_upstream_path is not configured")
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(c.cfg.ActiveUpstreamPath, raw, 0o644); err != nil {
			return nil, err
		}
		result := map[string]any{
			"profile": profile,
			"target":  c.cfg.ActiveUpstreamPath,
		}
		if c.cfg.ReloadServiceAfterSwitch != "" {
			cmdResult, err := c.runCommand(ctx, "systemctl", "reload", c.cfg.ReloadServiceAfterSwitch)
			result["reload"] = cmdResult
			return result, err
		}
		return result, nil
	case "drain_node":
		if c.cfg.DrainFilePath == "" {
			return nil, errors.New("drain_file_path is not configured")
		}
		if err := os.MkdirAll(filepath.Dir(c.cfg.DrainFilePath), 0o755); err != nil {
			return nil, err
		}
		reason, _ := params["reason"].(string)
		if err := os.WriteFile(c.cfg.DrainFilePath, []byte(reason), 0o644); err != nil {
			return nil, err
		}
		return map[string]any{
			"drainFile": c.cfg.DrainFilePath,
			"reason":    reason,
		}, nil
	case "collect_diagnostics":
		return c.collectDiagnostics(ctx), nil
	default:
		return nil, fmt.Errorf("unsupported action type: %s", actionType)
	}
}

func (c *Client) runCheck(ctx context.Context, check CheckConfig) heartbeatCheckResult {
	timeout := time.Duration(check.TimeoutMS)
	if timeout <= 0 {
		timeout = 5 * time.Second
	} else {
		timeout *= time.Millisecond
	}

	result := heartbeatCheckResult{
		Slug:      check.Slug,
		Name:      defaultString(check.Name, check.Slug),
		Protocol:  strings.ToLower(check.Protocol),
		Target:    check.Target,
		TimeoutMS: check.TimeoutMS,
	}

	started := time.Now()
	switch result.Protocol {
	case "http", "https", "head":
		method := http.MethodGet
		if result.Protocol == "head" {
			method = http.MethodHead
		}
		req, err := http.NewRequestWithContext(ctx, method, check.Target, nil)
		if err != nil {
			result.Status = "fail"
			result.Error = err.Error()
			return result
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			result.Status = "fail"
			result.Error = err.Error()
			return result
		}
		_ = resp.Body.Close()
		result.LatencyMS = time.Since(started).Milliseconds()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Error = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		}
	case "tcp":
		conn, err := net.DialTimeout("tcp", check.Target, timeout)
		if err != nil {
			result.Status = "fail"
			result.Error = err.Error()
			return result
		}
		_ = conn.Close()
		result.LatencyMS = time.Since(started).Milliseconds()
		result.Status = "pass"
	case "tls":
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", check.Target, &tls.Config{MinVersion: tls.VersionTLS12})
		if err != nil {
			result.Status = "fail"
			result.Error = err.Error()
			return result
		}
		_ = conn.Close()
		result.LatencyMS = time.Since(started).Milliseconds()
		result.Status = "pass"
	default:
		result.Status = "fail"
		result.Error = "unsupported protocol"
	}
	return result
}

func (c *Client) allowedService(raw any) (string, error) {
	service, _ := raw.(string)
	if service == "" {
		return "", errors.New("service is required")
	}
	for _, allowed := range c.cfg.AllowedServices {
		if allowed == service {
			return service, nil
		}
	}
	return "", fmt.Errorf("service %s is not allowlisted", service)
}

func (c *Client) runCommand(ctx context.Context, name string, args ...string) (map[string]any, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return map[string]any{
		"command": strings.Join(append([]string{name}, args...), " "),
		"stdout":  truncate(stdout.String(), 4096),
		"stderr":  truncate(stderr.String(), 4096),
	}, err
}

func (c *Client) collectDiagnostics(ctx context.Context) map[string]any {
	result := map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339),
	}

	if len(c.cfg.AllowedServices) > 0 {
		services := make(map[string]any, len(c.cfg.AllowedServices))
		for _, service := range c.cfg.AllowedServices {
			cmdResult, err := c.runCommand(ctx, "systemctl", "status", "--no-pager", service)
			if err != nil {
				cmdResult["error"] = err.Error()
			}
			services[service] = cmdResult
		}
		result["services"] = services
	}

	return result
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.WorkerURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("worker returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return err
		}
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
