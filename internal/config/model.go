package config

type Config struct {
	Log       LogConfig       `yaml:"log"`
	ACME      ACMEConfig      `yaml:"acme"`
	Limits    LimitsConfig    `yaml:"limits"`
	Challenge ChallengeConfig `yaml:"challenge"`
	WAF       WAFConfig       `yaml:"waf"`
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
	MaxURIBytes      int      `yaml:"max_uri_bytes"`
	MaxQueryBytes    int      `yaml:"max_query_bytes"`
	MaxParams        int      `yaml:"max_params"`
	MaxHeaderBytes   int      `yaml:"max_header_bytes"`
	MaxURLLength     int      `yaml:"max_url_length"`
	RiskThreshold    int      `yaml:"risk_threshold"`
	RiskTTLSeconds   int      `yaml:"risk_ttl_seconds"`
	RiskStatusWindow int      `yaml:"risk_status_window"`
	BanAfter         int      `yaml:"ban_after"`
	BanSeconds       int      `yaml:"ban_seconds"`
	Rate429BanAfter  int      `yaml:"rate_429_ban_after"`
	Rate429WindowSec int      `yaml:"rate_429_window_seconds"`
	Rate429BanSec    int      `yaml:"rate_429_ban_seconds"`
	WAFBanSec        int      `yaml:"waf_ban_seconds"`
	RatePolicies     []RatePolicy `yaml:"rate_policies"`
}

type RatePolicy struct {
	Name          string   `yaml:"name"`
	PathGlobs     []string `yaml:"path_globs"`
	RPS           float64  `yaml:"rps"`
	Burst         float64  `yaml:"burst"`
	Key           string   `yaml:"key"` // ip | ip_route
	BanAfter429   int      `yaml:"ban_after_429"`
	BanWindowSec  int      `yaml:"ban_window_seconds"`
	BanSec        int      `yaml:"ban_seconds"`
}

type ChallengeConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CookieTTLSeconds int      `yaml:"cookie_ttl_seconds"`
	BindIP           bool     `yaml:"bind_ip"`
	BindUA           bool     `yaml:"bind_ua"`
	ExemptGlobs      []string `yaml:"exempt_globs"`
}

type WAFConfig struct {
	Enabled             bool      `yaml:"enabled"`
	Mode                string    `yaml:"mode"`
	ScoreThreshold      int       `yaml:"score_threshold"`   // backward-compatible alias
	InboundThreshold    int       `yaml:"inbound_threshold"` // anomaly threshold
	ParanoiaLevel       int       `yaml:"paranoia_level"`    // 1..4
	MaxInspectBytes     int64     `yaml:"max_inspect_bytes"`
	MaxValuesPerCollection int    `yaml:"max_values_per_collection"`
	MaxTotalValues      int       `yaml:"max_total_values"`
	MaxJSONValues       int       `yaml:"max_json_values"`
	MaxBodyValues       int       `yaml:"max_body_values"`
	AllowedMethods      []string  `yaml:"allowed_methods"`
	BlockedContentTypes []string  `yaml:"blocked_content_types"`
	ExemptGlobs         []string  `yaml:"exempt_globs"`
	ExemptHosts         []string  `yaml:"exempt_hosts"`
	ExemptRuleIDs       []string            `yaml:"exempt_rule_ids"`
	ExemptRuleIDsByGlob map[string][]string `yaml:"exempt_rule_ids_by_glob"`
	Rules               []WAFRule `yaml:"rules"`
}

type WAFRule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Pattern     string   `yaml:"pattern"`
	Targets     []string `yaml:"targets"`
	Score       int      `yaml:"score"`
	Phase       string   `yaml:"phase"`
	Action      string   `yaml:"action"`
	Paranoia    int      `yaml:"paranoia"`
	Transforms  []string `yaml:"transforms"`
}
