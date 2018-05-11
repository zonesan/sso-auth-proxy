package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zonesan/clog"
)

func setBaseURL(urlStr string) string {
	// Make sure the given URL end with no slash
	if strings.HasSuffix(urlStr, "/") {
		return setBaseURL(strings.TrimSuffix(urlStr, "/"))
	}
	return urlStr
}

func httpsAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "http://") &&
		!strings.HasPrefix(strings.ToLower(addr), "https://") {
		return fmt.Sprintf("https://%s", addr)
	}

	return setBaseURL(addr)
}

func httpAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "http://") &&
		!strings.HasPrefix(strings.ToLower(addr), "https://") {
		return fmt.Sprintf("http://%s", addr)
	}
	return setBaseURL(addr)
}

func makeAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "https://") {
		return httpAddr(addr)
	}
	return httpsAddr(addr)
}

func makeAddrFromEnv(env string) string {
	addr := os.Getenv(env)
	if len(addr) == 0 {
		clog.Fatal(env, "must be specified.")
	}
	clog.Info(env, addr)
	return makeAddr(addr)
}
