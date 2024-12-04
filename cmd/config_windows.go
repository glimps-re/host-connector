//go:build windows
// +build windows

package cmd

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gonutz/wui/v2"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("AppData"), "gmhost", "config.yml")
	DefaultCacheLocation      = filepath.Join(os.Getenv("AppData"), "gmhost", "cache.db")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("AppData"), "gmhost", "quarantine")
)

func getConfigFile() (config string) {
	config = DefaultConfigPath
	home := os.Getenv("APPDATA")
	cfg := filepath.Join(home, "gmhost", "config.yml")
	if _, err := os.Stat(cfg); err == nil {
		return cfg
	}
	if _, err := os.Stat(config); err != nil {
		_, err = os.Create(config)
		if err != nil {
			Logger.Error("could not create config file", slog.String("location", config))
		}
	}
	return
}

type GuiErrorLog struct {
	h slog.Handler
}

func (h *GuiErrorLog) Enabled(ctx context.Context, level slog.Level) bool {
	return h.h.Enabled(ctx, level)
}

func (h *GuiErrorLog) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelError {
		buffer := bytes.Buffer{}
		log := slog.NewJSONHandler(&buffer, nil)
		log.Handle(ctx, r)
		wui.MessageBoxError("GMhost Error", buffer.String())
	}
	return h.h.Handle(ctx, r)
}

func (h *GuiErrorLog) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.h.WithAttrs(attrs)
}

func (h *GuiErrorLog) WithGroup(name string) slog.Handler {
	return h.h.WithGroup(name)
}

func init() {
	// dirty hack to check if we run as windowgui executable
	defer func() {
		if r := recover(); r != nil {
			Logger = slog.New(&GuiErrorLog{h: Logger.Handler()})
		}
	}()
	// must panic with windowsgui exe
	info, _ := os.Stderr.Stat()
	if info == nil {
		Logger = slog.New(&GuiErrorLog{h: Logger.Handler()})
	}
}
