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
	Delete     bool `yaml:"delete" desc:"delete malware files"`
	Quarantine bool `yaml:"quarantine" desc:"copy malware files in quarantine folder (locked)"`
	Print      bool `yaml:"print" desc:"print malware file information"`
	Log        bool `yaml:"log" desc:"log malware file information"`
}

type monitoringConfig struct {
	PreScan           bool          `yaml:"preScan" desc:"scan all files when starting to monitor"`
	ReScan            bool          `yaml:"reScan" desc:"re-scan all files periodically"`
	Period            time.Duration `yaml:"period" desc:"every period, walk through all files to check if they need to be scan again"`
	ModificationDelay time.Duration `yaml:"modificationDelay" desc:"modification delay before scanning a file"`
}

type gdetectConfig struct {
	URL      string        `yaml:"url" validate:"required" desc:"URL to gdetect API"`
	Token    string        `yaml:"token" validate:"required" password:"true" desc:"Token for gdetect API"`
	Timeout  time.Duration `yaml:"timeout" desc:"timeout allow to scan a single file"`
	Tags     []string      `yaml:"tags" desc:"tags add to each scan. those tags will be added to the default one (GMHost)"`
	Insecure bool          `yaml:"insecure" desc:"do no check GDetect certificates"`
}

type quarantineConfig struct {
	Location string `yaml:"location" desc:"path to keep quarantined files"`
	Password string `yaml:"password" desc:"password used to lock files in quarantine"`
}

type cacheConfig struct {
	Location     string        `yaml:"location" desc:"location of the cache file. if empty, cache will be volatile"`
	ScanValidity time.Duration `yaml:"scanValidity" desc:"when time since the last scan if lesser than ScanValidity the files won't be scan again"`
}

type exportConfig struct {
	Location string
}

type config struct {
	// global
	Config  string `yaml:"config"  desc:"path to configuration file"`
	Workers uint   `yaml:"workers" validate:"min=1,max=20" desc:"Number of workers to use"`
	Debug   bool   `yaml:"debug" desc:"print debug strings"`
	Verbose bool   `yaml:"verbose" desc:"print information strings"`
	Quiet   bool   `yaml:"quiet" desc:"print no information strings"`

	Paths []string `yaml:"paths" desc:"Paths to monitor"`

	Actions    actionsConfig    `yaml:"actions" desc:"actions done when a malware is found"`
	GDetect    gdetectConfig    `yaml:"gdetect" desc:"GDetect configuration"`
	Quarantine quarantineConfig `yaml:"quarantine" desc:"quarantine configuration"`
	Cache      cacheConfig      `yaml:"cache" desc:"cache configuration"`
	Monitoring monitoringConfig `yaml:"monitoring" desc:"monitoring configuration"`
	Export     exportConfig     `yaml:"export" desc:"export config"`
	Gui        bool
}
