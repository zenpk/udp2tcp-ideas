package util

import "log"

type MyLog struct {
	Loglevel int
}

const (
	LogLevelWarn  = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
)

var Log MyLog

func (m MyLog) Warn(format string, v ...any) {
	m.log(LogLevelWarn, format, v...)
}
func (m MyLog) Info(format string, v ...any) {
	m.log(LogLevelInfo, format, v...)
}

func (m MyLog) Debug(format string, v ...any) {
	m.log(LogLevelDebug, format, v...)
}

func (m MyLog) log(loglevel int, format string, v ...any) {
	if m.Loglevel < loglevel {
		return
	}
	log.Printf(format, v...)
}
