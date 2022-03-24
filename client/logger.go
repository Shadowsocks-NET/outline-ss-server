package client

import "go.uber.org/zap"

// logger is the shared logger instance used by this package.
// This variable must be assigned before calling any functions in this package.
var logger *zap.Logger

func SetLogger(l *zap.Logger) {
	logger = l
}
