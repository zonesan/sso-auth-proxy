package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/zonesan/clog"
)

type UpstreamProxy struct {
	handler   http.Handler
	wsHandler http.Handler
}

func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if u.wsHandler != nil && r.Header.Get("Connection") == "Upgrade" && r.Header.Get("Upgrade") == "websocket" {
		clog.Debug("ws")
		u.wsHandler.ServeHTTP(w, r)
	} else {
		clog.Debug("http")
		u.handler.ServeHTTP(w, r)
	}

}

func NewUpstreamProxy(target string) *UpstreamProxy {
	upstream, _ := url.Parse(target)
	httpProxy := httputil.NewSingleHostReverseProxy(upstream)

	upstreamQuery := upstream.RawQuery
	httpProxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", upstream.Host)
		req.Header.Add("Host", upstream.Host)
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.URL.Path = singleJoiningSlash(upstream.Path, req.URL.Path)
		if upstreamQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = upstreamQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = upstreamQuery + "&" + req.URL.RawQuery
		}

		fmt.Printf("%#v\n", req.Header)
	}

	if upstream.Scheme == "https" {
		httpProxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         upstream.Host,
			},
		}
	}

	var wsProxy *wsReverseProxy = nil
	wsScheme := "ws" + strings.TrimPrefix(upstream.Scheme, "http")
	wsURL := &url.URL{Scheme: wsScheme, Host: upstream.Host}
	wsProxy = NewSingleHostWsReverseProxy(wsURL)
	if wsScheme == "wss" {
		wsProxy.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         upstream.Host,
		}
	}
	return &UpstreamProxy{handler: httpProxy, wsHandler: wsProxy}
}
