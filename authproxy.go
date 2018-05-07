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

func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if u.wsHandler != nil && r.Header.Get("Connection") == "Upgrade" && r.Header.Get("Upgrade") == "websocket" {
		clog.Debug("ws")
		u.wsHandler.ServeHTTP(w, r)
	} else {
		clog.Debug("http")
		u.handler.ServeHTTP(w, r)
	}

}

type SsoProxy struct {
	serveMux http.Handler
}

func NewSsoProxy(upstream string) *SsoProxy {
	serveMux := http.NewServeMux()
	proxy := NewUpstreamProxy(upstream)
	serveMux.Handle("/", proxy)

	return &SsoProxy{
		serveMux: serveMux,
	}
}

func (p *SsoProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.Proxy(rw, req)
}

func (p *SsoProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	status := p.Authenticate(rw, req)
	if status == http.StatusInternalServerError {
		p.ErrorPage(rw, http.StatusInternalServerError,
			"Internal Error", "Internal Error")
	} else if status == http.StatusForbidden {
		p.SsoStart(rw, req)
	} else {
		p.serveMux.ServeHTTP(rw, req)
	}
	p.serveMux.ServeHTTP(rw, req)
}

func (p *SsoProxy) Authenticate(rw http.ResponseWriter, req *http.Request) int {
	clog.Error("TODO checking session/token, make/clear session etc.")
	_, _ = rw, req
	return http.StatusForbidden
	// return http.StatusAccepted
}

func (p *SsoProxy) SsoStart(rw http.ResponseWriter, req *http.Request) {
	clog.Error("TODO 302 to sso site.")

	// http.Redirect(xxxx
}

func (p *SsoProxy) ErrorPage(rw http.ResponseWriter, status int, reason, msg string) {
	_ = msg
	http.Error(rw, reason, status)
}

// func (p *SsoProxy) SsoStart(rw http.ResponseWriter, req *http.Request) {
// 	nonce, err := cookie.Nonce()
// 	if err != nil {
// 		p.ErrorPage(rw, 500, "Internal Error", err.Error())
// 		return
// 	}
// 	p.SetCSRFCookie(rw, req, nonce)
// 	redirect, err := p.GetRedirect(req)
// 	if err != nil {
// 		p.ErrorPage(rw, 500, "Internal Error", err.Error())
// 		return
// 	}
// 	redirectURI := p.GetRedirectURI(req.Host)
// 	http.Redirect(rw, req, p.provider.GetLoginURL(redirectURI, fmt.Sprintf("%v:%v", nonce, redirect)), 302)
// }

// func (p *UpstreamProxy) Authenticate(rw http.ResponseWriter, req *http.Request) int {
// 	var saveSession, clearSession, revalidated bool
// 	remoteAddr := getRemoteAddr(req)

// 	session, sessionAge, err := p.LoadCookiedSession(req)
// 	if err != nil && err != http.ErrNoCookie {
// 		log.Printf("%s %s", remoteAddr, err)
// 	}
// 	if session != nil && sessionAge > p.CookieRefresh && p.CookieRefresh != time.Duration(0) {
// 		log.Printf("%s refreshing %s old session cookie for %s (refresh after %s)", remoteAddr, sessionAge, session, p.CookieRefresh)
// 		saveSession = true
// 	}

// 	if ok, err := p.provider.RefreshSessionIfNeeded(session); err != nil {
// 		log.Printf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
// 		clearSession = true
// 		session = nil
// 	} else if ok {
// 		saveSession = true
// 		revalidated = true
// 	}

// 	if session != nil && session.IsExpired() {
// 		log.Printf("%s removing session. token expired %s", remoteAddr, session)
// 		session = nil
// 		saveSession = false
// 		clearSession = true
// 	}

// 	if saveSession && !revalidated && session != nil && session.AccessToken != "" {
// 		if !p.provider.ValidateSessionState(session) {
// 			log.Printf("%s removing session. error validating %s", remoteAddr, session)
// 			saveSession = false
// 			session = nil
// 			clearSession = true
// 		}
// 	}

// 	if session != nil && session.Email != "" && !p.Validator(session.Email) {
// 		log.Printf("%s Permission Denied: removing session %s", remoteAddr, session)
// 		session = nil
// 		saveSession = false
// 		clearSession = true
// 	}

// 	if saveSession && session != nil {
// 		err := p.SaveSession(rw, req, session)
// 		if err != nil {
// 			log.Printf("%s %s", remoteAddr, err)
// 			return http.StatusInternalServerError
// 		}
// 	}

// 	if clearSession {
// 		p.ClearSessionCookie(rw, req)
// 	}

// 	if session == nil {
// 		session, err = p.CheckBasicAuth(req)
// 		if err != nil {
// 			log.Printf("%s %s", remoteAddr, err)
// 		}
// 	}

// 	tokenProvidedByClient := false
// 	if session == nil {
// 		session, err = p.CheckRequestAuth(req)
// 		if err != nil {
// 			log.Printf("%s %s", remoteAddr, err)
// 		}
// 		tokenProvidedByClient = true
// 	}

// 	if session == nil {
// 		return http.StatusForbidden
// 	}

// 	// At this point, the user is authenticated. proxy normally
// 	if p.PassBasicAuth {
// 		req.SetBasicAuth(session.User, p.BasicAuthPassword)
// 		req.Header["X-Forwarded-User"] = []string{session.User}
// 		if session.Email != "" {
// 			req.Header["X-Forwarded-Email"] = []string{session.Email}
// 		}
// 	}
// 	if p.PassUserHeaders {
// 		req.Header["X-Forwarded-User"] = []string{session.User}
// 		if session.Email != "" {
// 			req.Header["X-Forwarded-Email"] = []string{session.Email}
// 		}
// 	}
// 	if p.SetXAuthRequest {
// 		rw.Header().Set("X-Auth-Request-User", session.User)
// 		if session.Email != "" {
// 			rw.Header().Set("X-Auth-Request-Email", session.Email)
// 		}
// 	}
// 	if ((!tokenProvidedByClient && p.PassAccessToken) || (tokenProvidedByClient && p.PassUserBearerToken)) && session.AccessToken != "" {
// 		req.Header["X-Forwarded-Access-Token"] = []string{session.AccessToken}
// 	}
// 	if session.Email == "" {
// 		rw.Header().Set("GAP-Auth", session.User)
// 	} else {
// 		rw.Header().Set("GAP-Auth", session.Email)
// 	}
// 	return http.StatusAccepted
// }
