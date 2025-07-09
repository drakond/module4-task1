package logger

import (
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func Init() error {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		return err
	}
	Logger = zapLogger.Sugar()
	return nil
}
