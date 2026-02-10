package config

type Config struct {
	Log       LogConfig       `yaml:"log"`
	ACME      ACMEConfig      `yaml:"acme"`
	Limits    LimitsConfig    `yaml:"limits"`
	Challenge ChallengeConfig `yaml:"challenge"`
	Servers   []Server        `yaml:"servers"`
}

type Server struct {
	Hostname string   `yaml:"hostname"`
	Handles  []Handle `yaml:"handles"`
}

type Handle struct {
	MatcherName string   `yaml:"matcher_name"`
	Matcher     *Matcher `yaml:"matcher"`
	StripPrefix string   `yaml:"strip_prefix"`
	Upstream    string   `yaml:"upstream"`
}

type Matcher struct {
	PathGlob string `yaml:"path_glob"`
}

type LogConfig struct {
	Output string `yaml:"output"`
	Format string `yaml:"format"`
}

type ACMEConfig struct {
	Email       string `yaml:"email"`
	CA          string `yaml:"ca"`
	Staging     bool   `yaml:"staging"`
	KeyType     string `yaml:"key_type"`
	RenewWindow string `yaml:"renew_window"`
	StoragePath string `yaml:"storage_path"`
}

type LimitsConfig struct {
	RPS              float64  `yaml:"rps"`
	Burst            float64  `yaml:"burst"`
	ConnLimit        int      `yaml:"conn_limit"`
	WSConnLimit      int      `yaml:"ws_conn_limit"`
	WhitelistIPs     []string `yaml:"whitelist_ips"`
	MaxBodyBytes     int64    `yaml:"max_body_bytes"`
	MaxHeaderBytes   int      `yaml:"max_header_bytes"`
	MaxURLLength     int      `yaml:"max_url_length"`
	RiskThreshold    int      `yaml:"risk_threshold"`
	RiskTTLSeconds   int      `yaml:"risk_ttl_seconds"`
	RiskStatusWindow int      `yaml:"risk_status_window"`
	BanAfter         int      `yaml:"ban_after"`
	BanSeconds       int      `yaml:"ban_seconds"`
}

type ChallengeConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CookieTTLSeconds int      `yaml:"cookie_ttl_seconds"`
	BindIP           bool     `yaml:"bind_ip"`
	BindUA           bool     `yaml:"bind_ua"`
	ExemptGlobs      []string `yaml:"exempt_globs"`
}
