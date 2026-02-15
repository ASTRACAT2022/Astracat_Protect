package config

import (
	"path/filepath"
	"strings"
)

func LoadConfig(path string) (*Config, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return LoadYAML(path)
	default:
		return LoadCaddyfile(path)
	}
}
