package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zonesan/clog"
)

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	clog.Debug("from", r.RemoteAddr, r.Method, r.URL.RequestURI(), r.Proto)

	auth(r)
	ssoproxy.ServeHTTP(w, r)
}

func auth(req *http.Request) {
	req.Header.Add("X-test-Header", "dfproxy")
	clog.Debug("TO DO sso check")
}

var ssoproxy = NewUpstreamProxy("http://localhost:8080")

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
