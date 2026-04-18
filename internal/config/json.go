package config

// JSON is valid YAML, so we can reuse the same parser and YAML tags.
func LoadJSON(path string) (*Config, error) {
	return LoadYAML(path)
}
