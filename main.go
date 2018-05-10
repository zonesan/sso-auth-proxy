package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zonesan/clog"
)

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	// clog.Debug("from", r.RemoteAddr, r.Method, r.URL.RequestURI(), r.Proto)
	ssoproxy.ServeHTTP(w, r)
}

var ssoproxy *SsoProxy
var loginBaseURL, redeemBaseURL string

func main() {

	router := mux.NewRouter()

	// router.HandleFunc(`/api/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/oapi/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/apis/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/ws/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/{r:.*}`, ssoproxy.ServeHTTP)

	router.HandleFunc(`/{r:.*}`, ssoHandler)

	clog.Debug("listening on port 9090 ...")
	clog.Fatal(http.ListenAndServe(":9090", router))
}

func init() {
	// upstream := os.Getenv("SSO_UPSTREAM_URL")
	// if len(upstream) == 0 {
	// 	clog.Fatal("SSO_UPSTREAM_URL must be specified.")
	// }
	// target := makeAddr(upstream)

	redeemBaseURL = makeAddrFromEnv("SSO_REDEEM_BASE_URL")
	loginBaseURL = makeAddrFromEnv("SSO_LOGIN_BASE_URL")
	upstream := makeAddrFromEnv("SSO_UPSTREAM_URL")
	ssoproxy = NewSsoProxy(upstream)
	clog.Info("Upstream target:", upstream)
}
