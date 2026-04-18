package config

type Config struct {
	Log           LogConfig           `yaml:"log"`
	ACME          ACMEConfig          `yaml:"acme"`
	HTTP3         HTTP3Config         `yaml:"http3"`
	ThreatIntel   ThreatIntelConfig   `yaml:"threat_intel"`
	BotManagement BotManagementConfig `yaml:"bot_management"`
	Limits        LimitsConfig        `yaml:"limits"`
	Challenge     ChallengeConfig     `yaml:"challenge"`
	WAF           WAFConfig           `yaml:"waf"`
	AI            AIConfig            `yaml:"ai"`
	AutoShield    AutoShieldConfig    `yaml:"auto_shield"`
	Servers       []Server            `yaml:"servers"`
}

type Server struct {
	Hostname string     `yaml:"hostname"`
	TLS      *ServerTLS `yaml:"tls"`
	// AutoShieldEnabled overrides global auto_shield.enabled for this hostname.
	// nil means "use global setting".
	AutoShieldEnabled *bool    `yaml:"auto_shield_enabled"`
	Handles           []Handle `yaml:"handles"`
}

type ServerTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type Handle struct {
	MatcherName string   `yaml:"matcher_name"`
	Matcher     *Matcher `yaml:"matcher"`
	StripPrefix string   `yaml:"strip_prefix"`
	Mode        string   `yaml:"mode"`
	LBPolicy    string   `yaml:"lb_policy"`
	Upstream    string   `yaml:"upstream"`
	Upstreams   []string `yaml:"upstreams"`
}

type Matcher struct {
	PathGlob  string `yaml:"path_glob"`
	PathExact string `yaml:"path_exact"`
	PathRegex string `yaml:"path_regex"`
}

type LogConfig struct {
	Output string `yaml:"output"`
	Format string `yaml:"format"`
}

type ACMEConfig struct {
	Email             string `yaml:"email"`
	CA                string `yaml:"ca"`
	Staging           bool   `yaml:"staging"`
	KeyType           string `yaml:"key_type"`
	RenewWindow       string `yaml:"renew_window"`
	StoragePath       string `yaml:"storage_path"`
	OnDemandTLS       bool   `yaml:"on_demand_tls"`
	DNS01Enabled      bool   `yaml:"dns01_enabled"`
	DNSIssueHook      string `yaml:"dns_issue_hook"`
	DNSRenewHook      string `yaml:"dns_renew_hook"`
	DNSHookTimeoutSec int    `yaml:"dns_hook_timeout_seconds"`
	DNSStoragePath    string `yaml:"dns_storage_path"`
}

type HTTP3Config struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type LimitsConfig struct {
	RPS              float64      `yaml:"rps"`
	Burst            float64      `yaml:"burst"`
	ConnLimit        int          `yaml:"conn_limit"`
	WSConnLimit      int          `yaml:"ws_conn_limit"`
	WhitelistIPs     []string     `yaml:"whitelist_ips"`
	MaxBodyBytes     int64        `yaml:"max_body_bytes"`
	MaxURIBytes      int          `yaml:"max_uri_bytes"`
	MaxQueryBytes    int          `yaml:"max_query_bytes"`
	MaxParams        int          `yaml:"max_params"`
	MaxHeaderBytes   int          `yaml:"max_header_bytes"`
	MaxURLLength     int          `yaml:"max_url_length"`
	RiskThreshold    int          `yaml:"risk_threshold"`
	RiskTTLSeconds   int          `yaml:"risk_ttl_seconds"`
	RiskStatusWindow int          `yaml:"risk_status_window"`
	BanAfter         int          `yaml:"ban_after"`
	BanSeconds       int          `yaml:"ban_seconds"`
	Rate429BanAfter  int          `yaml:"rate_429_ban_after"`
	Rate429WindowSec int          `yaml:"rate_429_window_seconds"`
	Rate429BanSec    int          `yaml:"rate_429_ban_seconds"`
	WAFBanSec        int          `yaml:"waf_ban_seconds"`
	RatePolicies     []RatePolicy `yaml:"rate_policies"`
}

type RatePolicy struct {
	Name         string   `yaml:"name"`
	PathGlobs    []string `yaml:"path_globs"`
	RPS          float64  `yaml:"rps"`
	Burst        float64  `yaml:"burst"`
	Key          string   `yaml:"key"` // ip | ip_route
	BanAfter429  int      `yaml:"ban_after_429"`
	BanWindowSec int      `yaml:"ban_window_seconds"`
	BanSec       int      `yaml:"ban_seconds"`
}

type ChallengeConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CookieTTLSeconds int      `yaml:"cookie_ttl_seconds"`
	BindIP           bool     `yaml:"bind_ip"`
	BindUA           bool     `yaml:"bind_ua"`
	ExemptGlobs      []string `yaml:"exempt_globs"`
}

type WAFConfig struct {
	Enabled                bool                `yaml:"enabled"`
	Mode                   string              `yaml:"mode"`
	ScoreThreshold         int                 `yaml:"score_threshold"`   // backward-compatible alias
	InboundThreshold       int                 `yaml:"inbound_threshold"` // anomaly threshold
	ParanoiaLevel          int                 `yaml:"paranoia_level"`    // 1..4
	Presets                []string            `yaml:"presets"`
	MaxInspectBytes        int64               `yaml:"max_inspect_bytes"`
	MaxValuesPerCollection int                 `yaml:"max_values_per_collection"`
	MaxTotalValues         int                 `yaml:"max_total_values"`
	MaxJSONValues          int                 `yaml:"max_json_values"`
	MaxBodyValues          int                 `yaml:"max_body_values"`
	AllowedMethods         []string            `yaml:"allowed_methods"`
	BlockedContentTypes    []string            `yaml:"blocked_content_types"`
	ExemptGlobs            []string            `yaml:"exempt_globs"`
	ExemptHosts            []string            `yaml:"exempt_hosts"`
	ExemptRuleIDs          []string            `yaml:"exempt_rule_ids"`
	ExemptRuleIDsByGlob    map[string][]string `yaml:"exempt_rule_ids_by_glob"`
	Rules                  []WAFRule           `yaml:"rules"`
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

type AIConfig struct {
	Enabled               bool    `yaml:"enabled"`
	LearningMode          bool    `yaml:"learning_mode"`
	Backend               string  `yaml:"backend"` // builtin | onnx | tflite
	ModelPath             string  `yaml:"model_path"`
	ONNXCommand           string  `yaml:"onnx_command"`
	TFLiteCommand         string  `yaml:"tflite_command"`
	StatePath             string  `yaml:"state_path"`
	MinSamples            int     `yaml:"min_samples"`
	ChallengeThreshold    float64 `yaml:"challenge_threshold"`
	RateLimitThreshold    float64 `yaml:"rate_limit_threshold"`
	BlockThreshold        float64 `yaml:"block_threshold"`
	MaxBodyInspectBytes   int64   `yaml:"max_body_inspect_bytes"`
	CommandTimeoutMS      int     `yaml:"command_timeout_ms"`
	UpdateProfilesOnBlock bool    `yaml:"update_profiles_on_block"`
}

type ThreatIntelConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Action         string   `yaml:"action"` // block | challenge | rate_limit | log
	RefreshSeconds int      `yaml:"refresh_seconds"`
	IPFeeds        []string `yaml:"ip_feeds"`
	ASNFeeds       []string `yaml:"asn_feeds"`
	JA3Feeds       []string `yaml:"ja3_feeds"`
	IPs            []string `yaml:"ips"`
	ASNs           []string `yaml:"asns"`
	JA3            []string `yaml:"ja3"`
	ASNHeader      string   `yaml:"asn_header"`
	JA3Header      string   `yaml:"ja3_header"`
}

type BotManagementConfig struct {
	Enabled          bool         `yaml:"enabled"`
	BadAction        string       `yaml:"bad_action"` // block | challenge | rate_limit
	BypassWAFForGood bool         `yaml:"bypass_waf_for_good"`
	GoodPatterns     []string     `yaml:"good_patterns"`
	BadPatterns      []string     `yaml:"bad_patterns"`
	Profiles         []BotProfile `yaml:"profiles"`
}

type BotProfile struct {
	Name     string `yaml:"name"`
	Kind     string `yaml:"kind"` // good | bad
	Pattern  string `yaml:"pattern"`
	Action   string `yaml:"action"`   // for bad profiles
	Priority int    `yaml:"priority"` // high first
}

type AutoShieldConfig struct {
	Enabled                 bool `yaml:"enabled"`
	WindowSeconds           int  `yaml:"window_seconds"`
	MinRequests             int  `yaml:"min_requests"`
	ProbePathThreshold      int  `yaml:"probe_path_threshold"`
	HighErrorRatioPct       int  `yaml:"high_error_ratio_pct"`
	HighRateLimitedRatioPct int  `yaml:"high_rate_limited_ratio_pct"`
	ScoreThreshold          int  `yaml:"score_threshold"`
	BanSeconds              int  `yaml:"ban_seconds"`
}
