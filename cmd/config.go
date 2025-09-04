package cmd

import (
	"time"
)

var (
	DefaultTimeout           = 5 * time.Minute
	DefaultWorkers           = 4
	DefaultScanValidity      = time.Hour * 24 * 7
	DefaultModificationDelay = time.Second * 30
	DefaultMaxFileSize       = "100MiB"
)

var conf = &config{
	Config:      DefaultConfigPath,
	Workers:     DefaultWorkers,
	MaxFileSize: DefaultMaxFileSize,
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
	PluginConfig: pluginConfig{
		Location: DefaultPluginsLocation,
		Plugins:  map[string]string{},
	},
}

type actionsConfig struct {
	Delete     bool `mapstructure:"delete" yaml:"delete" desc:"delete malware files"`
	Quarantine bool `mapstructure:"quarantine" yaml:"quarantine" desc:"copy malware files in quarantine folder (locked)"`
	Print      bool `mapstructure:"print" yaml:"print" desc:"print malware file information"`
	Log        bool `mapstructure:"log" yaml:"log" desc:"log malware file information"`
	Move       bool `mapstructure:"moveLegit" yaml:"moveLegit" desc:"move legit files after analysis"`
}

type monitoringConfig struct {
	PreScan           bool          `mapstructure:"preScan" yaml:"preScan" desc:"scan all files when starting to monitor"`
	ReScan            bool          `mapstructure:"reScan" yaml:"reScan" desc:"re-scan all files periodically"`
	Period            time.Duration `mapstructure:"period" yaml:"period" desc:"every period, walk through all files to check if they need to be scan again"`
	ModificationDelay time.Duration `mapstructure:"modificationDelay" yaml:"modificationDelay" desc:"modification delay before scanning a file"`
}

type gdetectConfig struct {
	URL       string        `mapstructure:"url" yaml:"url" validate:"required" desc:"URL to gdetect API"`
	Token     string        `mapstructure:"token" yaml:"token" validate:"required" password:"true" desc:"Token for gdetect API"`
	Timeout   time.Duration `mapstructure:"timeout" yaml:"timeout" desc:"timeout allow to scan a single file"`
	Tags      []string      `mapstructure:"tags" yaml:"tags" desc:"tags add to each scan. those tags will be added to the default one (GMHost)"`
	Insecure  bool          `mapstructure:"insecure" yaml:"insecure" desc:"do no check GDetect certificates"`
	Syndetect bool          `mapstructure:"syndetect" yaml:"syndetect" desc:"use syndetect API to analyze files"`
}

type quarantineConfig struct {
	Location string `mapstructure:"location" yaml:"location" desc:"path to keep quarantined files"`
	Password string `mapstructure:"password" yaml:"password" desc:"password used to lock files in quarantine"`
}

type cacheConfig struct {
	Location     string        `mapstructure:"location" yaml:"location" desc:"location of the cache file. if empty, cache will be volatile"`
	ScanValidity time.Duration `mapstructure:"scanValidity" yaml:"scanValidity" desc:"when time since the last scan if lesser than ScanValidity the files won't be scan again"`
}

type moveConfig struct {
	Destination string `mapstructure:"destination" yaml:"destination" desc:"destination where legit files are moved"`
	Source      string `mapstructure:"source" yaml:"source" desc:"to be move, a legit file must be in source folder of sub folders"`
}

type printConfig struct {
	Location string `mapstructure:"location" yaml:"location" desc:"location of the report logs"`
}

type pluginConfig struct {
	Location string            `mapstructure:"folder" yaml:"folder" desc:"folder containing plugins"`
	Plugins  map[string]string `mapstructure:"plugins" yaml:"plugins" desc:"active plugins, PLUGIN_NAME:CONFIG_FILE"`
}

type config struct {
	// global
	Config      string `yaml:"config" desc:"path to configuration file"`
	Workers     int    `mapstructure:"workers" yaml:"workers" validate:"min=1,max=20" desc:"Number of workers to use"`
	Extract     bool   `mapstructure:"extract" yaml:"extract" desc:"extract big archive to send it to gmalware"`
	MaxFileSize string `mapstructure:"maxFileSize" yaml:"maxFileSize" desc:"max file size to push to gmalware"`
	Debug       bool   `mapstructure:"debug" yaml:"debug" desc:"print debug strings"`
	Verbose     bool   `mapstructure:"verbose" yaml:"verbose" desc:"print information strings"`
	Quiet       bool   `mapstructure:"quiet" yaml:"quiet" desc:"print no information strings"`

	Paths []string `yaml:"paths" desc:"Paths to monitor"`

	Actions      actionsConfig    `mapstructure:"actions" yaml:"actions" desc:"actions done when a malware is found"`
	GDetect      gdetectConfig    `mapstructure:"gdetect" yaml:"gdetect" desc:"GDetect configuration"`
	Quarantine   quarantineConfig `mapstructure:"quarantine" yaml:"quarantine" desc:"quarantine configuration"`
	Cache        cacheConfig      `mapstructure:"cache" yaml:"cache" desc:"cache configuration"`
	Monitoring   monitoringConfig `mapstructure:"monitoring" yaml:"monitoring" desc:"monitoring configuration"`
	Move         moveConfig       `mapstructure:"move" yaml:"move" desc:"move legit files configuration"`
	Print        printConfig      `mapstructure:"print" yaml:"print" desc:"print report configuration"`
	PluginConfig pluginConfig     `mapstructure:"plugins" yaml:"plugins" desc:"plugins configuration"`
	Gui          bool
}
