package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const profilesBucket = "ai_profiles"

const (
	ActionAllow     = "allow"
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionRateLimit = "rate_limit"
)

type Config struct {
	Enabled               bool
	LearningMode          bool
	Backend               string
	ModelPath             string
	ONNXCommand           string
	TFLiteCommand         string
	StatePath             string
	MinSamples            int
	ChallengeThreshold    float64
	RateLimitThreshold    float64
	BlockThreshold        float64
	MaxBodyInspectBytes   int64
	CommandTimeoutMS      int
	UpdateProfilesOnBlock bool
}

type Decision struct {
	Action string
	Score  float64
	Reason string
}

type Engine struct {
	cfg Config
	db  *bbolt.DB
}

type features struct {
	PathShape      string  `json:"path_shape"`
	PathLength     float64 `json:"path_length"`
	QueryLength    float64 `json:"query_length"`
	HeaderCount    float64 `json:"header_count"`
	QueryParams    float64 `json:"query_params"`
	BodyLength     float64 `json:"body_length"`
	SuspiciousHits float64 `json:"suspicious_hits"`
}

type runningStat struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"mean"`
	M2    float64 `json:"m2"`
}

type profile struct {
	Count        int64       `json:"count"`
	UpdatedAtUTC string      `json:"updated_at_utc"`
	PathLength   runningStat `json:"path_length"`
	QueryLength  runningStat `json:"query_length"`
	HeaderCount  runningStat `json:"header_count"`
	QueryParams  runningStat `json:"query_params"`
	BodyLength   runningStat `json:"body_length"`
}

type modelInput struct {
	Backend  string   `json:"backend"`
	Model    string   `json:"model"`
	Host     string   `json:"host"`
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Features features `json:"features"`
}

type modelOutput struct {
	Score  float64 `json:"score"`
	Action string  `json:"action"`
	Reason string  `json:"reason"`
}

func New(cfg Config) (*Engine, error) {
	normalizeConfig(&cfg)
	if !cfg.Enabled {
		return &Engine{cfg: cfg}, nil
	}

	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o755); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(cfg.StatePath, 0o600, &bbolt.Options{Timeout: 500 * time.Millisecond})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(profilesBucket))
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Engine{cfg: cfg, db: db}, nil
}

func (e *Engine) Enabled() bool {
	return e != nil && e.cfg.Enabled
}

func (e *Engine) Close() error {
	if e == nil || e.db == nil {
		return nil
	}
	return e.db.Close()
}

func (e *Engine) Inspect(r *http.Request) (Decision, error) {
	if !e.Enabled() {
		return Decision{Action: ActionAllow}, nil
	}

	f, err := extractFeatures(r, e.cfg.MaxBodyInspectBytes)
	if err != nil {
		return Decision{Action: ActionAllow}, err
	}
	key := profileKey(normalizeHost(r.Host), strings.ToUpper(strings.TrimSpace(r.Method)), f.PathShape)

	p, err := e.loadProfile(key)
	if err != nil {
		return Decision{Action: ActionAllow}, err
	}

	builtinScore := scoreFromProfile(p, f)
	finalScore := builtinScore
	reason := "builtin"
	overrideAction := ""

	if out, modelErr := e.inferModel(r, f); modelErr == nil {
		finalScore = out.Score
		if out.Reason != "" {
			reason = out.Reason
		} else {
			reason = e.cfg.Backend
		}
		overrideAction = normalizeAction(out.Action)
	}

	decision := decideAction(e.cfg, p.Count, finalScore, overrideAction, reason)
	if decision.Action == ActionAllow || decision.Action == ActionChallenge || decision.Action == ActionRateLimit || e.cfg.UpdateProfilesOnBlock {
		if err := e.updateProfile(key, p, f); err != nil {
			return decision, err
		}
	}
	return decision, nil
}

func (e *Engine) inferModel(r *http.Request, f features) (modelOutput, error) {
	backend := strings.ToLower(strings.TrimSpace(e.cfg.Backend))
	if backend == "" || backend == "builtin" {
		return modelOutput{}, fmt.Errorf("builtin backend")
	}

	cmd := ""
	switch backend {
	case "onnx":
		cmd = strings.TrimSpace(e.cfg.ONNXCommand)
	case "tflite":
		cmd = strings.TrimSpace(e.cfg.TFLiteCommand)
	default:
		return modelOutput{}, fmt.Errorf("unsupported ai backend: %s", backend)
	}
	if cmd == "" {
		return modelOutput{}, fmt.Errorf("%s command is empty", backend)
	}

	in := modelInput{
		Backend:  backend,
		Model:    e.cfg.ModelPath,
		Host:     normalizeHost(r.Host),
		Method:   strings.ToUpper(strings.TrimSpace(r.Method)),
		Path:     r.URL.Path,
		Features: f,
	}
	return runModelCommand(cmd, in, e.cfg.CommandTimeoutMS)
}

func runModelCommand(template string, in modelInput, timeoutMS int) (modelOutput, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return modelOutput{}, err
	}

	cmdStr := strings.ReplaceAll(template, "{model}", shellEscape(in.Model))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", cmdStr)
	cmd.Stdin = bytes.NewReader(payload)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return modelOutput{}, fmt.Errorf("model command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	raw := strings.TrimSpace(out.String())
	if raw == "" {
		return modelOutput{}, fmt.Errorf("model command returned empty output")
	}

	var parsed modelOutput
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		if parsed.Score < 0 {
			parsed.Score = 0
		}
		parsed.Action = normalizeAction(parsed.Action)
		return parsed, nil
	}

	if score, err := strconv.ParseFloat(raw, 64); err == nil {
		return modelOutput{Score: score}, nil
	}
	return modelOutput{}, fmt.Errorf("invalid model output: %s", raw)
}

func decideAction(cfg Config, profileCount int64, score float64, overrideAction, reason string) Decision {
	action := ActionAllow
	if cfg.LearningMode && profileCount < int64(cfg.MinSamples) {
		return Decision{
			Action: ActionAllow,
			Score:  score,
			Reason: fmt.Sprintf("learning profile_count=%d min=%d", profileCount, cfg.MinSamples),
		}
	}

	if overrideAction != "" {
		action = overrideAction
	} else {
		switch {
		case score >= cfg.BlockThreshold:
			action = ActionBlock
		case score >= cfg.RateLimitThreshold:
			action = ActionRateLimit
		case score >= cfg.ChallengeThreshold:
			action = ActionChallenge
		default:
			action = ActionAllow
		}
	}
	return Decision{
		Action: action,
		Score:  score,
		Reason: reason,
	}
}

func normalizeAction(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ActionAllow:
		return ActionAllow
	case "block", "deny", "forbid":
		return ActionBlock
	case "challenge", "captcha":
		return ActionChallenge
	case "rate", "rate-limit", "ratelimit":
		return ActionRateLimit
	default:
		return ""
	}
}

func (e *Engine) loadProfile(key string) (profile, error) {
	out := profile{}
	if e.db == nil {
		return out, nil
	}
	err := e.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(profilesBucket))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(key))
		if len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

func (e *Engine) updateProfile(key string, p profile, f features) error {
	if e.db == nil {
		return nil
	}
	p.Count++
	p.UpdatedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	p.PathLength = updateStat(p.PathLength, f.PathLength)
	p.QueryLength = updateStat(p.QueryLength, f.QueryLength)
	p.HeaderCount = updateStat(p.HeaderCount, f.HeaderCount)
	p.QueryParams = updateStat(p.QueryParams, f.QueryParams)
	p.BodyLength = updateStat(p.BodyLength, f.BodyLength)

	return e.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(profilesBucket))
		if b == nil {
			return fmt.Errorf("profiles bucket is missing")
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), raw)
	})
}

func updateStat(s runningStat, value float64) runningStat {
	s.Count++
	delta := value - s.Mean
	s.Mean += delta / float64(s.Count)
	delta2 := value - s.Mean
	s.M2 += delta * delta2
	return s
}

func zscore(s runningStat, value float64) float64 {
	if s.Count < 10 {
		return 0
	}
	variance := s.M2 / float64(maxInt64(1, s.Count-1))
	if variance < 1 {
		variance = 1
	}
	stddev := math.Sqrt(variance)
	if stddev <= 0 {
		return 0
	}
	return math.Abs(value-s.Mean) / stddev
}

func scoreFromProfile(p profile, f features) float64 {
	zs := []float64{
		zscore(p.PathLength, f.PathLength),
		zscore(p.QueryLength, f.QueryLength),
		zscore(p.HeaderCount, f.HeaderCount),
		zscore(p.QueryParams, f.QueryParams),
		zscore(p.BodyLength, f.BodyLength),
	}
	var total float64
	for _, z := range zs {
		total += minFloat(3, z)
	}
	shapeAnomaly := total / float64(len(zs)) * 2
	signature := minFloat(5, f.SuspiciousHits*1.5)
	return shapeAnomaly + signature
}

func extractFeatures(r *http.Request, bodyLimit int64) (features, error) {
	query := r.URL.Query()
	body, err := readBodySample(r, bodyLimit)
	if err != nil {
		return features{}, err
	}
	return features{
		PathShape:      pathShape(r.URL.Path),
		PathLength:     float64(len(r.URL.Path)),
		QueryLength:    float64(len(r.URL.RawQuery)),
		HeaderCount:    float64(len(r.Header)),
		QueryParams:    float64(countQueryParams(query)),
		BodyLength:     float64(len(body)),
		SuspiciousHits: float64(suspiciousHits(r.URL.Path + "?" + r.URL.RawQuery + "\n" + body)),
	}, nil
}

func readBodySample(r *http.Request, limit int64) (string, error) {
	if r == nil || r.Body == nil || limit <= 0 {
		return "", nil
	}
	chunk, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(chunk), r.Body))
	if int64(len(chunk)) > limit {
		chunk = chunk[:limit]
	}
	return string(chunk), nil
}

func countQueryParams(q url.Values) int {
	total := 0
	for _, vals := range q {
		total += len(vals)
		if len(vals) == 0 {
			total++
		}
	}
	return total
}

var (
	intRE  = regexp.MustCompile(`^\d+$`)
	hexRE  = regexp.MustCompile(`^[a-f0-9]{16,}$`)
	uuidRE = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

func pathShape(path string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(path)), "/")
	if len(parts) == 0 {
		return "/"
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		switch {
		case intRE.MatchString(part):
			out = append(out, ":int")
		case uuidRE.MatchString(part):
			out = append(out, ":uuid")
		case hexRE.MatchString(part):
			out = append(out, ":hex")
		case len(part) > 40:
			out = append(out, ":token")
		default:
			out = append(out, part)
		}
		if len(out) >= 6 {
			break
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

func suspiciousHits(raw string) int {
	v := strings.ToLower(raw)
	signatures := []string{
		"union select",
		"sleep(",
		"benchmark(",
		"<script",
		"javascript:",
		"onerror=",
		"../",
		"%2e%2e",
		"${jndi",
		"{{",
		"<?php",
	}
	hits := 0
	for _, s := range signatures {
		if strings.Contains(v, s) {
			hits++
		}
	}
	return hits
}

func profileKey(host, method, shape string) string {
	if host == "" {
		host = "_"
	}
	if method == "" {
		method = "_"
	}
	if shape == "" {
		shape = "/"
	}
	return host + "|" + method + "|" + shape
}

func normalizeHost(v string) string {
	out := strings.ToLower(strings.TrimSpace(v))
	out = strings.TrimSuffix(out, ".")
	if idx := strings.Index(out, ":"); idx != -1 {
		out = out[:idx]
	}
	return out
}

func shellEscape(v string) string {
	if v == "" {
		return ""
	}
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func normalizeConfig(cfg *Config) {
	cfg.Backend = strings.ToLower(strings.TrimSpace(cfg.Backend))
	if cfg.Backend == "" {
		cfg.Backend = "builtin"
	}
	if cfg.StatePath == "" {
		cfg.StatePath = "/data/ai/state.db"
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = 50
	}
	if cfg.ChallengeThreshold <= 0 {
		cfg.ChallengeThreshold = 5
	}
	if cfg.RateLimitThreshold <= 0 {
		cfg.RateLimitThreshold = 7
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 9
	}
	if cfg.MaxBodyInspectBytes <= 0 {
		cfg.MaxBodyInspectBytes = 8192
	}
	if cfg.CommandTimeoutMS <= 0 {
		cfg.CommandTimeoutMS = 25
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
