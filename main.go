package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/zonesan/clog"
)

var proxy = initProxy()

func initProxy() *httputil.ReverseProxy {
	origin, _ := url.Parse("https://prd.dataos.io")

	reverseProxy := httputil.NewSingleHostReverseProxy(origin)

	reverseProxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host

		// wildcardIndex := strings.IndexAny(path, "*")
		// proxyPath := singleJoiningSlash(origin.Path, req.URL.Path[wildcardIndex:])
		// if strings.HasSuffix(proxyPath, "/") && len(proxyPath) > 1 {
		// 	proxyPath = proxyPath[:len(proxyPath)-1]
		// }
		// req.URL.Path = proxyPath
	}
	reverseProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return reverseProxy
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	clog.Debug(r.URL.Path)

	auth()
	proxy.ServeHTTP(w, r)
}

func auth() {
	clog.Debug("TO DO sso check")
}

func main() {

	router := mux.NewRouter()

	router.HandleFunc(`/api/{r:.*}`, ssoHandler)
	router.HandleFunc(`/oapi/{r:.*}`, ssoHandler)
	router.HandleFunc(`/apis/{r:.*}`, ssoHandler)
	router.HandleFunc(`/{r:.*}`, proxy.ServeHTTP)

	clog.Debug("listening on port 9090 ...")
	clog.Fatal(http.ListenAndServe(":9090", router))
}
