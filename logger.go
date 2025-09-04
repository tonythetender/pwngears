package pwngears

import (
	"fmt"
	"log/slog"
	"os"
)

var LogLevel slog.LevelVar

func NewDefaultLogger(logLevel string) (*slog.Logger, error) {
	switch logLevel {
	case "DEBUG", "debug":
		LogLevel.Set(slog.LevelDebug)
	case "INFO", "info":
		LogLevel.Set(slog.LevelInfo)
	case "WARN", "warn":
		LogLevel.Set(slog.LevelWarn)
	case "ERROR", "error":
		LogLevel.Set(slog.LevelError)
	case "IGNORE", "ignore":
		LogLevel.Set(12)
	default:
		return nil, fmt.Errorf("invalid log level: %v", logLevel)
	}

	opts := &slog.HandlerOptions{
		Level: &LogLevel,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)

	return slog.New(handler), nil
}
