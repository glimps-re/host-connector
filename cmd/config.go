package cmd

import (
	"time"
)

var (
	DefaultTimeout                         = 5 * time.Minute
	DefaultWorkers           uint          = 4
	DefaultScanValidity                    = time.Hour * 24 * 7
	DefaultModificationDelay time.Duration = time.Second * 30
)

var conf = &config{
	Config:  DefaultConfigPath,
	Workers: uint(DefaultWorkers),
	Actions: actionsConfig{
		Delete:     true,
		Quarantine: true,
		Print:      true,
		Log:        true,
	},
	GDetect: gdetectConfig{
		Timeout: DefaultTimeout,
	},
	Quarantine: quarantineConfig{
		Password: "infected",
	},
	Cache: cacheConfig{
		ScanValidity: DefaultScanValidity,
		Location:     ":file::memory",
	},
}

type actionsConfig struct {
	Delete     bool `yaml:"delete" json:"delete" desc:"delete malware files"`
	Quarantine bool `yaml:"quarantine" json:"quarantine" desc:"copy malware files in quarantine folder (locked)"`
	Print      bool `yaml:"print" json:"print" desc:"print malware file information"`
	Log        bool `yaml:"log" json:"log" desc:"log malware file information"`
}

type monitoringConfig struct {
	PreScan           bool          `json:"pre_scan,omitempty" yaml:"preScan" desc:"scan all files when starting to monitor"`
	ReScan            bool          `json:"re_scan,omitempty" yaml:"reScan" desc:"re scan all files periodically"`
	Period            time.Duration `json:"period,omitempty" yaml:"period" desc:"every period, walk through all files to check if they need to be scan again"`
	ModificationDelay time.Duration `json:"modification_delay" yaml:"modificationDelay" desc:"modification delay before scanning a file"`
}

type gdetectConfig struct {
	URL      string        `yaml:"url" validate:"required" desc:"URL to gdetect API" json:"url"`
	Token    string        `yaml:"token" validate:"required" password:"true" desc:"Token for gdetect API" json:"token"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout" desc:"timeout allow to scan a single file"`
	Tags     []string      `yaml:"tags" desc:"tags add to GDetect analyses" json:"tags add to each scan. those tags will be added to the default one (GMHost)"`
	Insecure bool          `yaml:"insecure" json:"insecure" desc:"do no check GDetect certificates"`
}

type quarantineConfig struct {
	Location string `desc:"path to keep quarantined files" json:"location" yaml:"location"`
	Password string `json:"password" yaml:"password" desc:"password used to lock files in quarantine"`
}

type cacheConfig struct {
	Location     string        `json:"location" yaml:"location" desc:"location of the cache file. if empty, cache will be volatile"`
	ScanValidity time.Duration `json:"scan_validity" yaml:"scanValidity" desc:"when time since the last scan if lesser than ScanValidity the files won't be scan again"`
}

type exportConfig struct {
	Location string
}

type config struct {
	// global
	Config  string `json:"config" yaml:"config" desc:"path to configuration file"`
	Workers uint   `mapstructure:"workers" yaml:"workers" validate:"max=20,min=1" desc:"Number of workers to use" json:"workers"`
	Debug   bool   `mapstructure:"debug" yaml:"debug" desc:"print debug strings" json:"debug"`
	Verbose bool   `mapstructure:"verbose" yaml:"verbose" desc:"print information strings" json:"verbose"`
	Quiet   bool   `mapstructure:"quiet" yaml:"quiet" desc:"print no information strings" json:"quiet"`

	Paths []string `mapstructure:"paths" yaml:"paths" desc:"Paths to monitor" json:"paths"`

	Actions    actionsConfig    `json:"actions" yaml:"actions" desc:"actions done when a malware is found"`
	GDetect    gdetectConfig    `json:"gdetect" yaml:"gdetect" desc:"GDetect configuration"`
	Quarantine quarantineConfig `json:"quarantine" yaml:"quarantine" desc:"quarantine configuration"`
	Cache      cacheConfig      `json:"cache" yaml:"cache" desc:"cache configuration"`
	Monitoring monitoringConfig `json:"monitoring" yaml:"monitoring" desc:"monitoring configuration"`
	Export     exportConfig     `json:"export" yaml:"export" desc:"export config"`
}
