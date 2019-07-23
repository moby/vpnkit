package log

import (
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// SetLogger sets a new default logger
func SetLogger(l *logrus.Logger) {
	log = l
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}

func Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Println(s string) {
	log.Println(s)
}
