package main

import (
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"golift.io/xtractr"
)

type SevenZipExtractPlugin struct {
	sze          *sevenZipExtract
	pathToRemove []string
}

type Config struct {
	MaxFileSize          int      `yaml:"max_file_size,omitempty"`
	MaxExtractedElements int      `yaml:"max_extracted_elements,omitempty"`
	DefaultPasswords     []string `yaml:"default_passwords,omitempty"`
	SevenZipPath         string   `yaml:"seven_zip_path,omitempty"`
	TOption              bool     `yaml:"t_option,omitempty"`
}

var (
	HCPlugin SevenZipExtractPlugin

	//go:embed 7zzs
	SevenZip []byte
)

func (p *SevenZipExtractPlugin) Init(configPath string, hcc plugins.HCContext) error {
	var conf Config
	if configPath == "" {
		conf = Config{
			MaxFileSize:          1024 * 1024,
			MaxExtractedElements: 1000,
			DefaultPasswords:     []string{"infected"},
		}
	}

	if conf.SevenZipPath == "" {
		var err error
		if conf.SevenZipPath, err = p.get7zzs(); err != nil {
			return err
		}
		fname, err := exec.LookPath("7zzs")
		if err != nil {
			return err
		}
		conf.SevenZipPath, err = filepath.Abs(fname)
		if err != nil {
			return err
		}
	}
	p.sze = newSevenZipExtract(extractorConfig{
		MaxFileSize:          conf.MaxFileSize,
		MaxExtractedElements: conf.MaxExtractedElements,
		DefaultPasswords:     conf.DefaultPasswords,
	}, conf.SevenZipPath, conf.TOption)

	hcc.SetXTractFile(p.XtractFile)
	return nil
}

func (p *SevenZipExtractPlugin) get7zzs() (string, error) {
	fname, err := exec.LookPath("7zzs")
	if err == nil {
		p, e := filepath.Abs(fname)
		if e != nil {
			return "", e
		}
		return p, nil
	}
	f, err := os.CreateTemp(os.TempDir(), "7zzs")
	if err != nil {
		return "", err
	}
	p.pathToRemove = append(p.pathToRemove, f.Name())
	defer f.Close()
	_, err = f.Write(SevenZip)
	if err != nil {
		return "", err
	}
	err = f.Chmod(0o755)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}

func (p *SevenZipExtractPlugin) XtractFile(xFile *xtractr.XFile) (size int64, files []string, volumes []string, err error) {
	dest, err := os.MkdirTemp(os.TempDir(), "extracted*")
	if err != nil {
		return
	}
	p.pathToRemove = append(p.pathToRemove, dest)
	result, err := p.sze.extract(xFile.FilePath, dest, []string{}, []string{})
	if err != nil {
		return
	}
	for _, ep := range result.extractedFiles {
		files = append(files, ep.Path)
	}
	return xtractr.ExtractFile(xFile)
}

func (p *SevenZipExtractPlugin) Close(_ context.Context) error { //nolint unparam // it's needed for interface
	for _, p := range p.pathToRemove {
		os.RemoveAll(p)
	}
	return nil
}

func main() {}
