package server

import (
	"time"

	"astracat-protect/internal/config"
	"astracat-protect/internal/proxy"
)

// resolveWSConfig returns the effective WebSocket configuration
// for a single handle. The rules are:
//
//   - If the handle sets a WebSocket override and that override
//     is disabled, the global setting is ignored (WS is off).
//   - If the handle override is enabled, fields that are zero in
//     the override fall back to the global section.
//   - If the handle has no override, the global section is used
//     as-is (a nil return means WS is fully disabled for the
//     handle, which lets the handler skip constructing the
//     WebSocket proxy entirely).
func resolveWSConfig(global config.WebSocketConfig, override *config.WebSocketConfig) *config.WebSocketConfig {
	if override == nil {
		if global.Enabled {
			g := global
			return &g
		}
		return nil
	}
	// Per-handle override always wins on the Enabled flag —
	// the operator can disable WS for one route while leaving
	// it on globally.
	if !override.Enabled {
		return nil
	}
	merged := *override
	if merged.HandshakeTimeout == "" {
		merged.HandshakeTimeout = global.HandshakeTimeout
	}
	if merged.ReadTimeout == "" {
		merged.ReadTimeout = global.ReadTimeout
	}
	if merged.WriteTimeout == "" {
		merged.WriteTimeout = global.WriteTimeout
	}
	if merged.MaxMessageBytes == 0 {
		merged.MaxMessageBytes = global.MaxMessageBytes
	}
	if merged.PingInterval == "" {
		merged.PingInterval = global.PingInterval
	}
	if merged.PongTimeout == "" {
		merged.PongTimeout = global.PongTimeout
	}
	if len(merged.AllowedOrigins) == 0 {
		merged.AllowedOrigins = global.AllowedOrigins
	}
	if len(merged.Subprotocols) == 0 {
		merged.Subprotocols = global.Subprotocols
	}
	return &merged
}

// buildProxyWSConfig converts a parsed config.WebSocketConfig
// into the runtime proxy.WSConfig. The string-form duration
// fields are parsed with time.ParseDuration; an unparseable
// value is treated as zero and silently disabled, mirroring the
// permissive behaviour of the rest of the configuration.
func buildProxyWSConfig(in config.WebSocketConfig) proxy.WSConfig {
	return proxy.WSConfig{
		HandshakeTimeout: parseDurationOrZero(in.HandshakeTimeout),
		ReadTimeout:      parseDurationOrZero(in.ReadTimeout),
		WriteTimeout:     parseDurationOrZero(in.WriteTimeout),
		MaxMessageBytes:  in.MaxMessageBytes,
		PingInterval:     parseDurationOrZero(in.PingInterval),
		PongTimeout:      parseDurationOrZero(in.PongTimeout),
		AllowedOrigins:   append([]string(nil), in.AllowedOrigins...),
		Subprotocols:     append([]string(nil), in.Subprotocols...),
	}
}

func parseDurationOrZero(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
