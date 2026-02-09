package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func LoadCaddyfile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := defaultConfig()

	type ctx int
	const (
		ctxTop ctx = iota
		ctxServer
		ctxLog
		ctxLogGlobal
		ctxRoute
		ctxHandle
	)

	currentCtx := ctxTop
	var currentServer *Server
	var currentHandle *Handle
	var routeHandles []Handle
	matchers := map[string]Matcher{}

	lineNo := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "}" {
			switch currentCtx {
			case ctxHandle:
				if currentHandle.Upstream == "" {
					return nil, fmt.Errorf("line %d: handle missing reverse_proxy", lineNo)
				}
				if currentHandle.MatcherName != "" {
					m, ok := matchers[currentHandle.MatcherName]
					if !ok {
						return nil, fmt.Errorf("line %d: unknown matcher %s", lineNo, currentHandle.MatcherName)
					}
					currentHandle.Matcher = &m
				}
				routeHandles = append(routeHandles, *currentHandle)
				currentHandle = nil
				currentCtx = ctxRoute
				continue
			case ctxRoute:
				currentServer.Handles = append(currentServer.Handles, routeHandles...)
				routeHandles = nil
				matchers = map[string]Matcher{}
				currentCtx = ctxServer
				continue
			case ctxLog:
				currentCtx = ctxServer
				continue
			case ctxLogGlobal:
				currentCtx = ctxTop
				continue
			case ctxServer:
				cfg.Servers = append(cfg.Servers, *currentServer)
				currentServer = nil
				currentCtx = ctxTop
				continue
			default:
				return nil, fmt.Errorf("line %d: unexpected '}'", lineNo)
			}
		}

		switch currentCtx {
		case ctxTop:
			if line == "log {" {
				currentCtx = ctxLogGlobal
				continue
			}
			if strings.HasSuffix(line, "{") {
				host := strings.TrimSpace(strings.TrimSuffix(line, "{"))
				if host == "" {
					return nil, fmt.Errorf("line %d: empty hostname", lineNo)
				}
				currentServer = &Server{Hostname: host}
				currentCtx = ctxServer
				continue
			}
			return nil, fmt.Errorf("line %d: expected hostname block", lineNo)
		case ctxServer:
			if line == "route {" {
				currentCtx = ctxRoute
				continue
			}
			if line == "log {" {
				currentCtx = ctxLog
				continue
			}
			if strings.HasPrefix(line, "reverse_proxy ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: reverse_proxy requires single upstream", lineNo)
				}
				currentServer.Handles = append(currentServer.Handles, Handle{Upstream: parts[1]})
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported directive: %s", lineNo, line)
		case ctxLog:
			if strings.HasPrefix(line, "output ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: output requires a value", lineNo)
				}
				cfg.Log.Output = parts[1]
				continue
			}
			if strings.HasPrefix(line, "format ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: format requires console or json", lineNo)
				}
				cfg.Log.Format = parts[1]
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported log directive: %s", lineNo, line)
		case ctxLogGlobal:
			if strings.HasPrefix(line, "output ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: output requires a value", lineNo)
				}
				cfg.Log.Output = parts[1]
				continue
			}
			if strings.HasPrefix(line, "format ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: format requires console or json", lineNo)
				}
				cfg.Log.Format = parts[1]
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported log directive: %s", lineNo, line)
		case ctxRoute:
			if strings.HasPrefix(line, "@") {
				parts := strings.Fields(line)
				if len(parts) != 3 || parts[1] != "path" {
					return nil, fmt.Errorf("line %d: matcher must be '@name path /glob'", lineNo)
				}
				matchers[parts[0]] = Matcher{PathGlob: parts[2]}
				continue
			}
			if strings.HasPrefix(line, "handle") {
				if !strings.HasSuffix(line, "{") {
					return nil, fmt.Errorf("line %d: handle must open block", lineNo)
				}
				trimmed := strings.TrimSpace(strings.TrimSuffix(line, "{"))
				parts := strings.Fields(trimmed)
				var matcherName string
				if len(parts) == 2 {
					matcherName = parts[1]
				} else if len(parts) != 1 {
					return nil, fmt.Errorf("line %d: invalid handle syntax", lineNo)
				}
				currentHandle = &Handle{MatcherName: matcherName}
				currentCtx = ctxHandle
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported route directive: %s", lineNo, line)
		case ctxHandle:
			if strings.HasPrefix(line, "uri strip_prefix ") {
				parts := strings.Fields(line)
				if len(parts) != 3 {
					return nil, fmt.Errorf("line %d: strip_prefix requires a value", lineNo)
				}
				currentHandle.StripPrefix = parts[2]
				continue
			}
			if strings.HasPrefix(line, "reverse_proxy ") {
				parts := strings.Fields(line)
				if len(parts) != 2 {
					return nil, fmt.Errorf("line %d: reverse_proxy requires single upstream", lineNo)
				}
				currentHandle.Upstream = parts[1]
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported handle directive: %s", lineNo, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if currentCtx != ctxTop {
		return nil, fmt.Errorf("unexpected EOF: missing closing '}'")
	}

	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		Log:  LogConfig{Output: "stdout", Format: "console"},
		ACME: ACMEConfig{StoragePath: "/data/acme"},
		Limits: LimitsConfig{
			RPS:              20,
			Burst:            40,
			ConnLimit:        100,
			WSConnLimit:      20,
			MaxBodyBytes:     10 << 20,
			MaxHeaderBytes:   1 << 20,
			MaxURLLength:     2048,
			RiskThreshold:    5,
			RiskTTLSeconds:   600,
			RiskStatusWindow: 60,
			BanAfter:         3,
			BanSeconds:       3600,
		},
		Challenge: ChallengeConfig{
			Enabled:          true,
			CookieTTLSeconds: 1800,
			BindIP:           true,
			BindUA:           false,
			ExemptGlobs: []string{
				"/api/*",
				"/cabinet/ws*",
				"/.well-known/acme-challenge/*",
				"/healthz",
				"/metrics",
				"*.css",
				"*.js",
				"*.png",
				"*.woff2",
			},
		},
	}
}
