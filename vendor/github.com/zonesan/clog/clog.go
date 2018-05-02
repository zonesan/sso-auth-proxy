package clog

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
)

var (
	KNRM = "\x1B[0m"
	KBLD = "\x1B[1m"
	KITY = "\x1B[3m"
	KUND = "\x1B[4m"
	KRED = "\x1B[31m"
	KGRN = "\x1B[32m"
	KYEL = "\x1B[33m"
	KBLU = "\x1B[34m"
	KMAG = "\x1B[35m"
	KCYN = "\x1B[36m"
	KWHT = "\x1B[37m"
)

const (
	LOG_LEVEL_NONE = iota
	LOG_LEVEL_FATAL
	LOG_LEVEL_ERROR
	LOG_LEVEL_WARN
	LOG_LEVEL_INFO
	LOG_LEVEL_TRACE
	LOG_LEVEL_DEBUG
)

var logEnv = map[string]int{
	"none":  LOG_LEVEL_NONE,
	"fatal": LOG_LEVEL_FATAL,
	"error": LOG_LEVEL_ERROR,
	"warn":  LOG_LEVEL_WARN,
	"info":  LOG_LEVEL_INFO,
	"trace": LOG_LEVEL_TRACE,
	"debug": LOG_LEVEL_DEBUG,
}

var logLevel = LOG_LEVEL_DEBUG
var logfileFd *os.File

func trace() string {
	pc := make([]uintptr, 5) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[1]).Name()

	fName := strings.Split(f, "/")[strings.Count(f, "/")]

	//return fmt.Sprintf("%s() ", f)
	return fName + "() "
}

func tracef() string {
	pc := make([]uintptr, 5) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[1])
	file, line := f.FileLine(pc[1])
	fname := f.Name()

	fName := strings.Split(fname, "/")[strings.Count(fname, "/")]
	filename := strings.Split(file, "/")[strings.Count(file, "/")]

	//return fmt.Sprintf("%s() ", f)
	return fmt.Sprintf("[%s:%d] %s() ", filename, line, fName)
}

func SetLogLevel(level int) {
	logLevel = level
}

func GetLogLevel() (level int) {
	return logLevel
}

func SetLogFile(logfile string) {
	f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	} else {
		log.SetOutput(f)
		logfileFd = f
	}
}

func CloseLogFile() {
	if logfileFd != nil {
		logfileFd.Close()
		logfileFd = nil
	}
}

func SetOutput(w io.Writer) {
	log.SetOutput(w)
}

func Error(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_ERROR {
		s = KRED + "[ERROR] " + KNRM + tracef() + fmt.Sprintln(a...)
		log.Print(s)
	}
	return
}

func Errorf(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_ERROR {
		s = KRED + "[ERROR] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
	}
	return
}

func Fatal(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_FATAL {
		s = KRED + KBLD + "[FATAL] " + KNRM + tracef() + fmt.Sprintln(a...)
		log.Print(s)
		os.Exit(1)
	}
	return
}

func Fatalf(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_FATAL {
		s = KRED + KBLD + "[FATAL] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
		os.Exit(1)
	}
	return
}

func Info(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_INFO {
		//log.Print(KGRN+"[INFO] "+KNRM+tracef(), fmt.Sprintln(a...))
		s = fmt.Sprint(KGRN + "[INFO] " + KNRM + tracef() + fmt.Sprintln(a...))
		log.Print(s)
	}
	return
}

func Infof(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_INFO {
		s = KGRN + "[INFO] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
	}
	return
}

func Trace(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_TRACE {
		s = KMAG + "[TRACE] " + KNRM + tracef() + fmt.Sprintln(a...)
		log.Print(s)
	}
	return
}

func Tracef(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_TRACE {
		s = KMAG + "[TRACE] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
	}
	return
}

func Debug(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_DEBUG {
		s = KBLU + "[DEBUG] " + KNRM + tracef() + fmt.Sprintln(a...)
		log.Print(s)
	}
	return
}

func Debugf(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_DEBUG {
		s = KBLU + "[DEBUG] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
	}
	return
}

func Warn(a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_WARN {
		s = KYEL + "[WARNING] " + KNRM + tracef() + fmt.Sprintln(a...)
		log.Print(s)
	}
	return
}

func Warnf(format string, a ...interface{}) (s string) {
	checkLogEnv()
	if logLevel >= LOG_LEVEL_WARN {
		s = KYEL + "[WARNING] " + KNRM + tracef() + fmt.Sprintf(format, a...)
		log.Print(s)
	}
	return
}

func Println(a ...interface{}) (s string) {
	s = KGRN + "[INFO] " + KNRM + tracef() + fmt.Sprintln(a...)
	log.Print(s)
	return
}

func Printf(format string, a ...interface{}) (s string) {
	s = KGRN + "[INFO] " + KNRM + tracef() + fmt.Sprintf(format, a...)
	log.Print(s)
	return
}

func checkLogEnv() {
	lvl := os.Getenv("CLOG_LOGLEVEL")
	if len(lvl) > 0 {
		lvl = strings.ToLower(lvl)
		if level, ok := logEnv[lvl]; ok {
			if logLevel != level {
				//fmt.Printf("set log level to %v[%v]\n", lvl, level)
				logLevel = level
			}
		}
	}
}

func init() {
	checkLogEnv()
}

/*
func main() {
	fmt.Println(logLevel)
	Info("%s", "hello world!")
	Debug("%s", "hello world!")
	Error("%s", "hello world!")
	Warn("%s", "hello world!")
	Fatal("%s", "hello world!")
}


func init() {
	//log.SetFlags(log.Lshortfile | log.LstdFlags)
	fmt.Println(LOG_LEVEL_DEBUG, LOG_LEVEL_ERROR, LOG_LEVEL_FATAL, LOG_LEVEL_INFO, LOG_LEVEL_TRACE, LOG_LEVEL_WARN)
}
*/
