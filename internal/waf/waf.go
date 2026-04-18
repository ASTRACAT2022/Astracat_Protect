package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultMode             = "block"
	defaultThreshold        = 7
	defaultParanoia         = 1
	defaultMaxInspectBytes  = 64 << 10
	defaultMaxTransformPass = 2
	defaultMaxValuesPerColl = 200
	defaultMaxTotalValues   = 500
	defaultMaxJSONValues    = 300
	defaultMaxBodyValues    = 300
)

type RuleConfig struct {
	ID          string
	Description string
	Pattern     string
	Targets     []string
	Score       int
	Phase       string   // request|method|headers|body
	Action      string   // score|block|allow|log|challenge|rate_limit
	Paranoia    int      // 1..4
	Transforms  []string // lowercase,url_decode,html_decode,remove_nulls,compress_whitespace,path_normalize
}

type Config struct {
	Enabled                bool
	Mode                   string
	ScoreThreshold         int // backward-compatible alias of InboundThreshold
	InboundThreshold       int
	MaxInspectBytes        int64
	ParanoiaLevel          int
	Presets                []string
	MaxValuesPerCollection int
	MaxTotalValues         int
	MaxJSONValues          int
	MaxBodyValues          int
	AllowedMethods         []string
	BlockedContentTypes    []string
	Rules                  []RuleConfig
}

type InspectOptions struct {
	SkipRuleIDs map[string]struct{}
}

type Decision struct {
	Matched bool
	Blocked bool
	Action  string
	Score   int
	RuleIDs []string
	Reason  string
}

type Engine struct {
	enabled             bool
	mode                string
	inboundThreshold    int
	maxInspectBytes     int64
	paranoiaLevel       int
	maxValuesPerColl    int
	maxTotalValues      int
	maxJSONValues       int
	maxBodyValues       int
	allowedMethods      map[string]struct{}
	blockedContentTypes []*regexp.Regexp
	rules               []rule
}

type rule struct {
	id         string
	score      int
	paranoia   int
	phase      phase
	action     action
	regex      *regexp.Regexp
	targets    map[target]struct{}
	transforms []transform
}

type phase string

const (
	phaseRequest phase = "request"
	phaseMethod  phase = "method"
	phaseHeaders phase = "headers"
	phaseBody    phase = "body"
)

type action string

const (
	actionScore     action = "score"
	actionBlock     action = "block"
	actionAllow     action = "allow"
	actionLog       action = "log"
	actionChallenge action = "challenge"
	actionRateLimit action = "rate_limit"
)

type target string

const (
	targetMethod  target = "method"
	targetPath    target = "path"
	targetQuery   target = "query"
	targetHeaders target = "headers"
	targetBody    target = "body"
)

type transform string

const (
	tfLowercase         transform = "lowercase"
	tfURLDecode         transform = "url_decode"
	tfHTMLDecode        transform = "html_decode"
	tfRemoveNulls       transform = "remove_nulls"
	tfCompressWS        transform = "compress_whitespace"
	tfPathNormalize     transform = "path_normalize"
	tfTrimSpace         transform = "trim"
	tfCmdLineNormalize  transform = "cmdline"
	tfDecodeRepeatedURL transform = "url_decode_repeat"
)

func New(cfg Config) (*Engine, error) {
	e := &Engine{
		enabled:          cfg.Enabled,
		mode:             strings.ToLower(strings.TrimSpace(cfg.Mode)),
		maxInspectBytes:  cfg.MaxInspectBytes,
		paranoiaLevel:    cfg.ParanoiaLevel,
		maxValuesPerColl: cfg.MaxValuesPerCollection,
		maxTotalValues:   cfg.MaxTotalValues,
		maxJSONValues:    cfg.MaxJSONValues,
		maxBodyValues:    cfg.MaxBodyValues,
		allowedMethods:   map[string]struct{}{},
	}
	if e.mode == "" {
		e.mode = defaultMode
	}
	if e.mode != "block" && e.mode != "log" {
		return nil, fmt.Errorf("invalid waf mode: %s", cfg.Mode)
	}
	if e.maxInspectBytes <= 0 {
		e.maxInspectBytes = defaultMaxInspectBytes
	}
	if e.paranoiaLevel <= 0 {
		e.paranoiaLevel = defaultParanoia
	}
	if e.paranoiaLevel > 4 {
		e.paranoiaLevel = 4
	}
	if e.maxValuesPerColl <= 0 {
		e.maxValuesPerColl = defaultMaxValuesPerColl
	}
	if e.maxTotalValues <= 0 {
		e.maxTotalValues = defaultMaxTotalValues
	}
	if e.maxJSONValues <= 0 {
		e.maxJSONValues = defaultMaxJSONValues
	}
	if e.maxBodyValues <= 0 {
		e.maxBodyValues = defaultMaxBodyValues
	}

	threshold := cfg.InboundThreshold
	if threshold <= 0 {
		threshold = cfg.ScoreThreshold
	}
	if threshold <= 0 {
		threshold = defaultThreshold
	}
	e.inboundThreshold = threshold

	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
	}
	for _, m := range methods {
		nm := strings.ToUpper(strings.TrimSpace(m))
		if nm != "" {
			e.allowedMethods[nm] = struct{}{}
		}
	}

	for _, raw := range cfg.BlockedContentTypes {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + pat)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked content-type pattern %q: %w", pat, err)
		}
		e.blockedContentTypes = append(e.blockedContentTypes, re)
	}

	if !e.enabled {
		return e, nil
	}

	inputRules := cfg.Rules
	if len(inputRules) == 0 {
		inputRules = defaultRules()
	}
	if len(cfg.Presets) > 0 {
		inputRules = append(inputRules, presetRules(cfg.Presets)...)
	}
	for _, rc := range inputRules {
		r, err := compileRule(rc)
		if err != nil {
			return nil, err
		}
		e.rules = append(e.rules, r)
	}
	return e, nil
}

func (e *Engine) Enabled() bool {
	return e != nil && e.enabled
}

func (e *Engine) Inspect(r *http.Request, opts *InspectOptions) (Decision, error) {
	if !e.Enabled() {
		return Decision{}, nil
	}

	attrs, err := collectRequestAttrs(r, collectOptions{
		bodyLimit:        e.maxInspectBytes,
		maxValuesPerColl: e.maxValuesPerColl,
		maxTotalValues:   e.maxTotalValues,
		maxJSONValues:    e.maxJSONValues,
		maxBodyValues:    e.maxBodyValues,
	})
	if err != nil {
		return Decision{}, err
	}

	// Protocol enforcement: method allowlist.
	if len(e.allowedMethods) > 0 {
		if _, ok := e.allowedMethods[attrs.method]; !ok {
			return e.decide(Decision{
				Matched: true,
				Score:   10,
				RuleIDs: []string{"waf-protocol-method"},
				Reason:  "method not allowed",
			}, actionBlock), nil
		}
	}

	// Protocol enforcement: blocked content-types.
	if attrs.contentType != "" && len(e.blockedContentTypes) > 0 {
		for _, re := range e.blockedContentTypes {
			if re.MatchString(attrs.contentType) {
				return e.decide(Decision{
					Matched: true,
					Score:   10,
					RuleIDs: []string{"waf-protocol-content-type"},
					Reason:  "content-type not allowed",
				}, actionBlock), nil
			}
		}
	}
	if hasChunkedAndContentLength(r) {
		return e.decide(Decision{
			Matched: true,
			Score:   10,
			RuleIDs: []string{"waf-protocol-smuggling"},
			Reason:  "both chunked transfer-encoding and content-length present",
		}, actionBlock), nil
	}
	if hasInvalidTransferEncoding(r) {
		return e.decide(Decision{
			Matched: true,
			Score:   10,
			RuleIDs: []string{"waf-protocol-transfer-encoding"},
			Reason:  "invalid transfer-encoding",
		}, actionBlock), nil
	}

	matched := map[string]struct{}{}
	var anomalyScore int
	allowMatched := false
	explicitBlock := false
	explicitChallenge := false
	explicitRateLimit := false
	var reasons []string

	transformCache := map[string]string{}
	for _, rl := range e.rules {
		if opts != nil && len(opts.SkipRuleIDs) > 0 {
			if _, skip := opts.SkipRuleIDs[rl.id]; skip {
				continue
			}
		}
		if rl.paranoia > e.paranoiaLevel {
			continue
		}
		if !rl.match(attrs, transformCache) {
			continue
		}
		matched[rl.id] = struct{}{}
		switch rl.action {
		case actionAllow:
			allowMatched = true
			reasons = append(reasons, rl.id+": allow")
		case actionBlock:
			explicitBlock = true
			anomalyScore += rl.score
			reasons = append(reasons, rl.id+": block")
		case actionChallenge:
			explicitChallenge = true
			anomalyScore += rl.score
			reasons = append(reasons, rl.id+": challenge")
		case actionRateLimit:
			explicitRateLimit = true
			anomalyScore += rl.score
			reasons = append(reasons, rl.id+": rate_limit")
		case actionLog:
			reasons = append(reasons, rl.id+": log")
		default:
			anomalyScore += rl.score
			reasons = append(reasons, fmt.Sprintf("%s: score=%d", rl.id, rl.score))
		}
	}

	if len(matched) == 0 {
		return Decision{}, nil
	}

	ids := make([]string, 0, len(matched))
	for id := range matched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sort.Strings(reasons)

	decision := Decision{
		Matched: true,
		Score:   anomalyScore,
		RuleIDs: ids,
		Reason:  strings.Join(reasons, "; "),
	}

	if allowMatched && !explicitBlock && !explicitChallenge && !explicitRateLimit && anomalyScore < e.inboundThreshold {
		return e.decide(decision, actionAllow), nil
	}
	if explicitBlock {
		return e.decide(decision, actionBlock), nil
	}
	if explicitRateLimit {
		return e.decide(decision, actionRateLimit), nil
	}
	if explicitChallenge {
		return e.decide(decision, actionChallenge), nil
	}
	if anomalyScore >= e.inboundThreshold {
		return e.decide(decision, actionBlock), nil
	}
	return e.decide(decision, actionAllow), nil
}

func (e *Engine) decide(in Decision, want action) Decision {
	in.Blocked = false
	in.Action = string(actionAllow)
	if e.mode != "block" {
		return in
	}
	switch want {
	case actionBlock:
		in.Blocked = true
		in.Action = string(actionBlock)
	case actionChallenge:
		in.Action = string(actionChallenge)
	case actionRateLimit:
		in.Action = string(actionRateLimit)
	default:
		in.Action = string(actionAllow)
	}
	return in
}

type requestAttrs struct {
	method      string
	contentType string
	methodVals  []string
	pathVals    []string
	queryVals   []string
	headerVals  []string
	bodyVals    []string
}

type collectOptions struct {
	bodyLimit        int64
	maxValuesPerColl int
	maxTotalValues   int
	maxJSONValues    int
	maxBodyValues    int
}

func collectRequestAttrs(r *http.Request, opts collectOptions) (requestAttrs, error) {
	bodySample, err := readBodySample(r, opts.bodyLimit)
	if err != nil {
		return requestAttrs{}, err
	}
	bodyVals := []string{}

	ct := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if strings.EqualFold(ct, "multipart/form-data") {
		bodyVals = append(bodyVals, parseMultipartValues(bodySample, r.Header.Get("Content-Type"), opts.maxBodyValues)...)
	} else {
		if bodySample != "" {
			bodyVals = append(bodyVals, bodySample)
		}
		if strings.EqualFold(ct, "application/json") && bodySample != "" {
			bodyVals = append(bodyVals, flattenJSON(bodySample, opts.maxJSONValues)...)
		}
		if strings.EqualFold(ct, "application/x-www-form-urlencoded") && bodySample != "" {
			if vals, err := url.ParseQuery(bodySample); err == nil {
				for k, arr := range vals {
					for _, v := range arr {
						bodyVals = append(bodyVals, k+"="+v)
					}
				}
			}
		}
	}

	pathVals := capValues(pathSamples(r.URL), opts.maxValuesPerColl)
	queryVals := capValues(querySamples(r.URL), opts.maxValuesPerColl)
	headerVals := capValues(headerSamples(r.Header), opts.maxValuesPerColl)
	bodyVals = capValues(bodyVals, opts.maxValuesPerColl)
	pathVals, queryVals, headerVals, bodyVals = enforceTotalValues(opts.maxTotalValues, pathVals, queryVals, headerVals, bodyVals)

	return requestAttrs{
		method:      strings.ToUpper(strings.TrimSpace(r.Method)),
		contentType: ct,
		methodVals:  []string{strings.ToUpper(strings.TrimSpace(r.Method))},
		pathVals:    pathVals,
		queryVals:   queryVals,
		headerVals:  headerVals,
		bodyVals:    bodyVals,
	}, nil
}

func compileRule(cfg RuleConfig) (rule, error) {
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		return rule{}, fmt.Errorf("waf rule id is required")
	}
	pat := strings.TrimSpace(cfg.Pattern)
	if pat == "" {
		return rule{}, fmt.Errorf("waf rule %s has empty pattern", id)
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return rule{}, fmt.Errorf("waf rule %s invalid pattern: %w", id, err)
	}

	score := cfg.Score
	if score <= 0 {
		score = 5
	}
	paranoia := cfg.Paranoia
	if paranoia <= 0 {
		paranoia = 1
	}
	if paranoia > 4 {
		paranoia = 4
	}

	tgts, err := parseTargets(cfg.Targets)
	if err != nil {
		return rule{}, fmt.Errorf("waf rule %s: %w", id, err)
	}
	ph, err := parsePhase(cfg.Phase)
	if err != nil {
		return rule{}, fmt.Errorf("waf rule %s: %w", id, err)
	}
	act, err := parseAction(cfg.Action)
	if err != nil {
		return rule{}, fmt.Errorf("waf rule %s: %w", id, err)
	}
	tfs, err := parseTransforms(cfg.Transforms)
	if err != nil {
		return rule{}, fmt.Errorf("waf rule %s: %w", id, err)
	}

	return rule{
		id:         id,
		score:      score,
		paranoia:   paranoia,
		phase:      ph,
		action:     act,
		regex:      re,
		targets:    tgts,
		transforms: tfs,
	}, nil
}

func parseTargets(values []string) (map[target]struct{}, error) {
	if len(values) == 0 {
		return map[target]struct{}{
			targetPath:    {},
			targetQuery:   {},
			targetHeaders: {},
			targetBody:    {},
		}, nil
	}
	out := map[target]struct{}{}
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch v {
		case "method":
			out[targetMethod] = struct{}{}
		case "path", "uri", "url":
			out[targetPath] = struct{}{}
		case "query", "args":
			out[targetQuery] = struct{}{}
		case "headers", "header":
			out[targetHeaders] = struct{}{}
		case "body":
			out[targetBody] = struct{}{}
		default:
			return nil, fmt.Errorf("unknown target %q", raw)
		}
	}
	return out, nil
}

func parsePhase(v string) (phase, error) {
	n := strings.ToLower(strings.TrimSpace(v))
	if n == "" {
		return phaseRequest, nil
	}
	switch phase(n) {
	case phaseRequest, phaseMethod, phaseHeaders, phaseBody:
		return phase(n), nil
	default:
		return "", fmt.Errorf("unknown phase %q", v)
	}
}

func parseAction(v string) (action, error) {
	n := strings.ToLower(strings.TrimSpace(v))
	n = strings.ReplaceAll(n, "-", "_")
	if n == "" {
		return actionScore, nil
	}
	switch action(n) {
	case actionScore, actionBlock, actionAllow, actionLog, actionChallenge, actionRateLimit:
		return action(n), nil
	default:
		return "", fmt.Errorf("unknown action %q", v)
	}
}

func hasChunkedAndContentLength(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.ContentLength < 0 {
		return false
	}
	for _, te := range r.TransferEncoding {
		if strings.EqualFold(strings.TrimSpace(te), "chunked") {
			return true
		}
	}
	return false
}

func hasInvalidTransferEncoding(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, te := range r.TransferEncoding {
		n := strings.ToLower(strings.TrimSpace(te))
		if n == "" {
			continue
		}
		if n != "chunked" && n != "identity" {
			return true
		}
	}
	return false
}

func parseTransforms(values []string) ([]transform, error) {
	if len(values) == 0 {
		return []transform{tfURLDecode, tfHTMLDecode, tfRemoveNulls}, nil
	}
	out := make([]transform, 0, len(values))
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch transform(v) {
		case tfLowercase, tfURLDecode, tfHTMLDecode, tfRemoveNulls, tfCompressWS, tfPathNormalize, tfTrimSpace, tfCmdLineNormalize, tfDecodeRepeatedURL:
			out = append(out, transform(v))
		default:
			return nil, fmt.Errorf("unknown transform %q", raw)
		}
	}
	return out, nil
}

func (r rule) match(attrs requestAttrs, cache map[string]string) bool {
	collections := r.phaseCollections(attrs)

	for _, collection := range collections {
		for _, v := range collection {
			tv := applyTransformsCached(v, r.transforms, cache)
			if r.regex.MatchString(tv) {
				return true
			}
		}
	}
	return false
}

func (r rule) phaseCollections(attrs requestAttrs) [][]string {
	collections := make([][]string, 0, 5)
	include := func(t target) bool {
		if len(r.targets) == 0 {
			return true
		}
		_, ok := r.targets[t]
		return ok
	}
	switch r.phase {
	case phaseMethod:
		if include(targetMethod) {
			collections = append(collections, attrs.methodVals)
		}
	case phaseHeaders:
		if include(targetHeaders) {
			collections = append(collections, attrs.headerVals)
		}
	case phaseBody:
		if include(targetBody) {
			collections = append(collections, attrs.bodyVals)
		}
	default:
		if include(targetMethod) {
			collections = append(collections, attrs.methodVals)
		}
		if include(targetPath) {
			collections = append(collections, attrs.pathVals)
		}
		if include(targetQuery) {
			collections = append(collections, attrs.queryVals)
		}
		if include(targetHeaders) {
			collections = append(collections, attrs.headerVals)
		}
		if include(targetBody) {
			collections = append(collections, attrs.bodyVals)
		}
	}
	return collections
}

func applyTransforms(s string, tfs []transform) string {
	out := s
	for _, tf := range tfs {
		switch tf {
		case tfLowercase:
			out = strings.ToLower(out)
		case tfURLDecode:
			if decoded, err := url.QueryUnescape(out); err == nil {
				out = decoded
			}
		case tfDecodeRepeatedURL:
			for i := 0; i < defaultMaxTransformPass; i++ {
				decoded, err := url.QueryUnescape(out)
				if err != nil || decoded == out {
					break
				}
				out = decoded
			}
		case tfHTMLDecode:
			out = html.UnescapeString(out)
		case tfRemoveNulls:
			out = strings.ReplaceAll(out, "\x00", "")
		case tfCompressWS:
			out = strings.Join(strings.Fields(out), " ")
		case tfTrimSpace:
			out = strings.TrimSpace(out)
		case tfCmdLineNormalize:
			out = strings.ReplaceAll(out, "\\", "/")
			out = strings.ReplaceAll(out, "\"", "")
			out = strings.ReplaceAll(out, "'", "")
			out = strings.Join(strings.Fields(out), " ")
		case tfPathNormalize:
			trimmed := strings.TrimSpace(out)
			if trimmed == "" {
				break
			}
			if !strings.HasPrefix(trimmed, "/") {
				trimmed = "/" + trimmed
			}
			out = path.Clean(trimmed)
		}
	}
	return out
}

func applyTransformsCached(s string, tfs []transform, cache map[string]string) string {
	if cache == nil {
		return applyTransforms(s, tfs)
	}
	key := s + "\x1f" + transformsKey(tfs)
	if v, ok := cache[key]; ok {
		return v
	}
	v := applyTransforms(s, tfs)
	cache[key] = v
	return v
}

func transformsKey(tfs []transform) string {
	if len(tfs) == 0 {
		return ""
	}
	sb := strings.Builder{}
	for i, tf := range tfs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(string(tf))
	}
	return sb.String()
}

func pathSamples(u *url.URL) []string {
	if u == nil {
		return nil
	}
	out := []string{u.Path}
	if decoded, err := url.PathUnescape(u.Path); err == nil && decoded != u.Path {
		out = append(out, decoded)
	}
	return dedup(out)
}

func querySamples(u *url.URL) []string {
	if u == nil {
		return nil
	}
	out := make([]string, 0, 8)
	if raw := u.RawQuery; raw != "" {
		out = append(out, raw)
		if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
			out = append(out, decoded)
		}
	}
	for k, vals := range u.Query() {
		for _, v := range vals {
			out = append(out, k+"="+v)
		}
	}
	return dedup(out)
}

func headerSamples(h http.Header) []string {
	out := make([]string, 0, len(h)*2)
	for key, vals := range h {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") {
			continue
		}
		joined := strings.Join(vals, ",")
		out = append(out, key+": "+joined)
		out = append(out, joined)
	}
	return dedup(out)
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
	if len(chunk) == 0 {
		return "", nil
	}
	return string(chunk), nil
}

func flattenJSON(raw string, maxValues int) []string {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return nil
	}
	out := make([]string, 0, 64)
	walkJSON("", v, &out, maxValues)
	return capValues(dedup(out), maxValues)
}

func walkJSON(prefix string, v any, out *[]string, max int) {
	if max > 0 && len(*out) >= max {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			walkJSON(p, vv, out, max)
			if max > 0 && len(*out) >= max {
				return
			}
		}
	case []any:
		for i, vv := range x {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			walkJSON(p, vv, out, max)
			if max > 0 && len(*out) >= max {
				return
			}
		}
	case string:
		if prefix != "" {
			*out = append(*out, prefix+"="+x)
		}
		*out = append(*out, x)
	default:
		if prefix != "" {
			*out = append(*out, fmt.Sprintf("%s=%v", prefix, x))
		}
	}
}

func parseMultipartValues(bodySample string, contentTypeHeader string, maxValues int) []string {
	mediaType, params, err := mime.ParseMediaType(contentTypeHeader)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}

	mr := multipart.NewReader(strings.NewReader(bodySample), boundary)
	out := make([]string, 0, 32)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		name := strings.TrimSpace(part.FormName())
		fileName := strings.TrimSpace(part.FileName())
		partCT := strings.ToLower(strings.TrimSpace(strings.Split(part.Header.Get("Content-Type"), ";")[0]))
		if name != "" {
			out = append(out, "field="+name)
		}
		if fileName != "" {
			// Skip binary file payloads, only inspect metadata.
			if maxValues > 0 && len(out) >= maxValues {
				break
			}
			continue
		}
		if partCT != "" && !strings.HasPrefix(partCT, "text/") && !strings.Contains(partCT, "json") && !strings.Contains(partCT, "xml") && !strings.Contains(partCT, "form-urlencoded") {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(part, 2048))
		if len(b) > 0 {
			out = append(out, string(b))
		}
		if maxValues > 0 && len(out) >= maxValues {
			break
		}
	}
	return capValues(dedup(out), maxValues)
}

func capValues(values []string, max int) []string {
	if max <= 0 || len(values) <= max {
		return values
	}
	return values[:max]
}

func enforceTotalValues(max int, collections ...[]string) ([]string, []string, []string, []string) {
	if len(collections) != 4 || max <= 0 {
		return collections[0], collections[1], collections[2], collections[3]
	}
	remaining := max
	out := make([][]string, 4)
	for i, c := range collections {
		if remaining <= 0 {
			out[i] = nil
			continue
		}
		if len(c) > remaining {
			out[i] = c[:remaining]
			remaining = 0
			continue
		}
		out[i] = c
		remaining -= len(c)
	}
	return out[0], out[1], out[2], out[3]
}

func dedup(values []string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func defaultRules() []RuleConfig {
	return []RuleConfig{
		// PL1: protocol / obvious abuse
		{
			ID:          "waf-pl1-bad-method",
			Description: "Disallow dangerous legacy HTTP methods",
			Pattern:     `(?i)^(TRACE|TRACK|CONNECT|DEBUG)$`,
			Targets:     []string{"method"},
			Score:       10,
			Action:      "block",
			Paranoia:    1,
		},
		{
			ID:          "waf-pl1-path-traversal",
			Description: "Path traversal / LFI payloads",
			Pattern:     `(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|/etc/passwd|/proc/self/environ|/windows/win\.ini)`,
			Targets:     []string{"path", "query", "body"},
			Score:       9,
			Paranoia:    1,
		},
		{
			ID:          "waf-pl1-rce",
			Description: "Command injection primitives",
			Pattern:     `(?i)(\$\(|;\s*(wget|curl|nc|bash|sh)\b|\|\s*(wget|curl|nc|bash|sh)\b|\b(?:bash|sh|cmd|powershell)\b.{0,12}(?:-c|/c)\b)`,
			Targets:     []string{"path", "query", "body"},
			Score:       10,
			Paranoia:    1,
		},
		{
			ID:          "waf-pl1-scanner-ua",
			Description: "Known scanner user-agents",
			Pattern:     `(?i)(sqlmap|nikto|acunetix|nmap|masscan|nessus|zgrab|dirbuster|gobuster|nuclei)`,
			Targets:     []string{"headers"},
			Score:       7,
			Paranoia:    1,
		},

		// PL2: common injection payloads
		{
			ID:          "waf-pl2-sqli-union",
			Description: "SQLi UNION payloads",
			Pattern:     `(?i)(\bunion\b.{0,20}\bselect\b|\bselect\b.{0,20}\bfrom\b|\binformation_schema\b)`,
			Targets:     []string{"query", "body", "path"},
			Score:       6,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-sqli-boolean-time",
			Description: "Boolean/time SQLi payloads",
			Pattern:     `(?i)(\bor\b\s+1\s*=\s*1\b|\band\b\s+1\s*=\s*1\b|\bsleep\s*\(|\bbenchmark\s*\(|pg_sleep\s*\()`,
			Targets:     []string{"query", "body"},
			Score:       6,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-xss-basic",
			Description: "Basic XSS payloads",
			Pattern:     `(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|document\.cookie|<img\b[^>]*onerror\b)`,
			Targets:     []string{"query", "body", "path"},
			Score:       6,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-xss-svg",
			Description: "SVG/XLink XSS vectors",
			Pattern:     `(?i)(<svg\b|<math\b|xlink:href|data:text/html|vbscript:)`,
			Targets:     []string{"query", "body", "path"},
			Score:       6,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-nosqli",
			Description: "NoSQL operator injection",
			Pattern:     `(?i)(\$where|\$ne|\$gt|\$lt|\$regex|\$expr|\$function|mongo\.)`,
			Targets:     []string{"query", "body"},
			Score:       6,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-xxe",
			Description: "XXE payload markers",
			Pattern:     `(?is)(<!DOCTYPE|<!ENTITY|SYSTEM\s+\"file:|SYSTEM\s+\"https?:)`,
			Targets:     []string{"body", "query"},
			Score:       7,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-ssrf",
			Description: "SSRF metadata/localhost targets",
			Pattern:     `(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost(?::\d+)?|127\.0\.0\.1|0\.0\.0\.0|::1|file://|gopher://)`,
			Targets:     []string{"query", "body"},
			Score:       7,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-php-wrapper",
			Description: "PHP wrappers and stream abuse",
			Pattern:     `(?i)(php://|phar://|zip://|data://|expect://|glob://)`,
			Targets:     []string{"query", "body", "path"},
			Score:       7,
			Paranoia:    2,
		},
		{
			ID:          "waf-pl2-ldap-injection",
			Description: "LDAP filter injection markers",
			Pattern:     `(?i)(\(\s*\|\s*\(|\(\s*&\s*\(|\(\s*!\s*\(|\)\s*\(|\*\)\()`,
			Targets:     []string{"query", "body"},
			Score:       5,
			Paranoia:    2,
		},

		// PL3: advanced evasion and template injection
		{
			ID:          "waf-pl3-ssti",
			Description: "Template injection markers",
			Pattern:     `(?i)(\{\{[^}]+\}\}|\$\{[^}]+\}|<%[^%]+%>|__proto__|constructor\.prototype)`,
			Targets:     []string{"query", "body", "path"},
			Score:       7,
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-obfuscated-js",
			Description: "Obfuscated script sinks",
			Pattern:     `(?i)(String\.fromCharCode|atob\s*\(|eval\s*\(|setTimeout\s*\(|Function\s*\()`,
			Targets:     []string{"query", "body"},
			Score:       7,
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-crlf-injection",
			Description: "CRLF header injection payloads",
			Pattern:     `(?i)(%0d%0a|\r\n|\nset-cookie:|\nlocation:|\ncontent-length:)`,
			Targets:     []string{"query", "body", "path"},
			Score:       8,
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-deserialization-java",
			Description: "Java deserialization/gadget markers",
			Pattern:     `(?i)(java\.lang\.Runtime|org\.apache\.commons\.collections|ysoserial|rO0AB)`,
			Targets:     []string{"body", "headers", "query"},
			Score:       8,
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-path-evasion",
			Description: "Encoded path bypass/evasion",
			Pattern:     `(?i)(%2f|%5c|%252f|%255c|%c0%af|%u2215|%u2216)`,
			Targets:     []string{"path", "query"},
			Score:       6,
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-admin-bruteforce",
			Description: "Aggressive auth probing",
			Pattern:     `(?i)(/wp-login\.php|/xmlrpc\.php|/administrator|/admin\b|/manager/html|/boaform|/HNAP1/)`,
			Targets:     []string{"path"},
			Score:       5,
			Action:      "challenge",
			Paranoia:    3,
		},
		{
			ID:          "waf-pl3-api-abuse",
			Description: "High-risk sensitive endpoint probing",
			Pattern:     `(?i)(/actuator|/metrics|/debug|/internal|/private|/graphql\b|/v1/admin|/swagger|/openapi)`,
			Targets:     []string{"path"},
			Score:       5,
			Action:      "rate_limit",
			Paranoia:    3,
		},

		// PL4: strict signatures (higher false positive risk)
		{
			ID:          "waf-pl4-serialized-php",
			Description: "PHP object injection style payloads",
			Pattern:     `(?i)(O:\d+:\"[^\"]+\":\d+:\{|a:\d+:\{)`,
			Targets:     []string{"body", "query"},
			Score:       5,
			Paranoia:    4,
		},
		{
			ID:          "waf-pl4-jndi",
			Description: "JNDI lookup attempts",
			Pattern:     `(?i)\$\{jndi:(ldap|rmi|dns|iiop|http)s?:`,
			Targets:     []string{"headers", "query", "body"},
			Score:       10,
			Paranoia:    4,
		},
		{
			ID:          "waf-pl4-shell-obfuscation",
			Description: "Obfuscated shell command execution markers",
			Pattern:     `(?i)(base64\s+-d|/dev/tcp/|perl\s+-e|python\s+-c|ruby\s+-e|mkfifo|nc\s+-e|busybox\s+nc)`,
			Targets:     []string{"body", "query"},
			Score:       10,
			Paranoia:    4,
		},
		{
			ID:          "waf-pl4-sqli-stacked",
			Description: "Stacked query SQL injection payloads",
			Pattern:     `(?i)(;\s*(drop|alter|truncate|create|grant|revoke)\b|xp_cmdshell|sp_executesql|load_file\s*\()`,
			Targets:     []string{"query", "body"},
			Score:       9,
			Paranoia:    4,
		},
	}
}

func presetRules(presets []string) []RuleConfig {
	out := make([]RuleConfig, 0, 32)
	seen := map[string]struct{}{}
	add := func(rules []RuleConfig) {
		for _, r := range rules {
			id := strings.TrimSpace(r.ID)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, r)
		}
	}
	for _, raw := range presets {
		switch normalizePreset(raw) {
		case "wordpress":
			add(wordpressPresetRules())
		case "laravel":
			add(laravelPresetRules())
		case "nextjs":
			add(nextJSPresetRules())
		}
	}
	return out
}

func normalizePreset(v string) string {
	n := strings.ToLower(strings.TrimSpace(v))
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	switch n {
	case "wordpress", "wp":
		return "wordpress"
	case "laravel":
		return "laravel"
	case "nextjs", "next":
		return "nextjs"
	default:
		return ""
	}
}

func wordpressPresetRules() []RuleConfig {
	return []RuleConfig{
		{
			ID:          "waf-preset-wp-xmlrpc-abuse",
			Description: "WordPress xmlrpc abuse vectors",
			Pattern:     `(?i)^/xmlrpc\.php$|system\.multicall|pingback\.ping`,
			Targets:     []string{"path", "body"},
			Score:       8,
			Action:      "rate_limit",
			Paranoia:    2,
		},
		{
			ID:          "waf-preset-wp-admin-sensitive",
			Description: "WordPress sensitive files/endpoints",
			Pattern:     `(?i)^/(wp-config\.php|wp-admin/install\.php|wp-admin/setup-config\.php|wp-content/debug\.log|readme\.html)$`,
			Targets:     []string{"path"},
			Score:       10,
			Action:      "block",
			Paranoia:    2,
		},
		{
			ID:          "waf-preset-wp-php-upload-exec",
			Description: "WordPress uploaded PHP execution attempts",
			Pattern:     `(?i)^/wp-content/uploads/.*\.(php|phtml|phar)$`,
			Targets:     []string{"path"},
			Score:       10,
			Action:      "block",
			Paranoia:    3,
		},
		{
			ID:          "waf-preset-wp-login-bruteforce",
			Description: "WordPress login brute-force route",
			Pattern:     `(?i)^/wp-login\.php$`,
			Targets:     []string{"path"},
			Score:       6,
			Action:      "challenge",
			Paranoia:    2,
		},
	}
}

func laravelPresetRules() []RuleConfig {
	return []RuleConfig{
		{
			ID:          "waf-preset-laravel-env-exposure",
			Description: "Laravel env/config exposure",
			Pattern:     `(?i)^/(\.env|storage/logs/laravel\.log|vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php|_ignition/execute-solution)$`,
			Targets:     []string{"path"},
			Score:       10,
			Action:      "block",
			Paranoia:    2,
		},
		{
			ID:          "waf-preset-laravel-debug-probe",
			Description: "Laravel debug/profiler probing",
			Pattern:     `(?i)^/(telescope|horizon|ignition|debugbar|_ignition)`,
			Targets:     []string{"path"},
			Score:       7,
			Action:      "challenge",
			Paranoia:    2,
		},
		{
			ID:          "waf-preset-laravel-signed-url-abuse",
			Description: "Laravel signed URL tampering indicators",
			Pattern:     `(?i)(signature=.{0,8}$|expires=(?:0|1|2|3|4|5|6|7|8|9)$)`,
			Targets:     []string{"query"},
			Score:       6,
			Action:      "rate_limit",
			Paranoia:    3,
		},
	}
}

func nextJSPresetRules() []RuleConfig {
	return []RuleConfig{
		{
			ID:          "waf-preset-nextjs-image-ssrf",
			Description: "Next.js image optimizer SSRF vectors",
			Pattern:     `(?i)^/_next/image|url=(?:https?://)?(?:127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|::1|metadata\.google\.internal|file://)`,
			Targets:     []string{"path", "query"},
			Score:       9,
			Action:      "block",
			Paranoia:    2,
		},
		{
			ID:          "waf-preset-nextjs-internal-probe",
			Description: "Next.js internal route probing",
			Pattern:     `(?i)^/(?:_next/webpack-hmr|_next/static/webpack|_next/data/.+\.\./|_next/trace)`,
			Targets:     []string{"path"},
			Score:       8,
			Action:      "block",
			Paranoia:    3,
		},
		{
			ID:          "waf-preset-nextjs-api-abuse",
			Description: "High-risk Next.js auth/api probing",
			Pattern:     `(?i)^/(api/auth|api/admin|api/internal|api/debug)`,
			Targets:     []string{"path"},
			Score:       6,
			Action:      "challenge",
			Paranoia:    2,
		},
	}
}
