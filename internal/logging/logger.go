// Package logging configures and exposes a process-wide zerolog logger.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

const defaultDirPerm = 0o700

// Init initializes the global logger. If logFilePath is non-empty, logs are
// written to both stdout and the file. level may be "debug", "info", "warn", "error".
// The returned closer should be called once at process shutdown.
func Init(logFilePath, level string) (func(), error) {
	l := zerolog.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	}
	zerolog.SetGlobalLevel(l)

	writers := []io.Writer{os.Stdout}
	var f *os.File
	if logFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(logFilePath), defaultDirPerm); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		var err error
		f, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, f)
	}
	Log = zerolog.New(io.MultiWriter(writers...)).With().Timestamp().Logger()
	return func() {
		if f != nil {
			_ = f.Close()
		}
	}, nil
}

// Log is the package-global logger configured by Init.
var Log zerolog.Logger

// Get returns a pointer to the package-global logger.
func Get() *zerolog.Logger {
	return &Log
}
