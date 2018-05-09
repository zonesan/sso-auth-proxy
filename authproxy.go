package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/asiainfoldp/sso-auth-proxy/cookie"
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

		// fmt.Printf("%#v\n", req.Header)
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
		// clog.Debug("ws")
		u.wsHandler.ServeHTTP(w, r)
	} else {
		// clog.Debug("http")
		u.handler.ServeHTTP(w, r)
	}

}

type SsoProxy struct {
	serveMux     http.Handler
	SsoStartPath string
	AuthOnlyPath string
	CookieName   string
	CookieSeed   string
	CookieExpire time.Duration
	CookieCipher *cookie.Cipher
}

func NewSsoProxy(upstream string) *SsoProxy {
	serveMux := http.NewServeMux()
	proxy := NewUpstreamProxy(upstream)
	serveMux.Handle("/", proxy)

	var cipher *cookie.Cipher
	// if opts.PassAccessToken || (opts.CookieRefresh != time.Duration(0)) {
	// 	var err error
	// 	cipher, err = cookie.NewCipher(secretBytes(opts.CookieSecret))
	// 	if err != nil {
	// 		log.Fatal("cookie-secret error: ", err)
	// 	}
	// }

	return &SsoProxy{
		serveMux:     serveMux,
		SsoStartPath: "/ssostart",
		AuthOnlyPath: "/auth",
		CookieName:   "_datafoundry_sso_session",
		CookieSeed:   "D474F0undrys4n",
		CookieExpire: time.Minute * 30,
		CookieCipher: cipher,
	}
}

func (p *SsoProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	switch path := req.URL.Path; {
	case path == p.SsoStartPath:
		p.SsoStart(rw, req)
	case path == p.AuthOnlyPath:
		p.AuthOnly(rw, req)
	default:
		p.Proxy(rw, req)
	}
}

func (p *SsoProxy) AuthOnly(rw http.ResponseWriter, req *http.Request) {
	clog.Debugf("%#v", req.URL)
	req.ParseForm()
	token := req.FormValue("token")

	if len(token) > 0 {
		clog.Debug(token)
		user, err := p.Redeem(token)
		if err != nil {
			clog.Error(err)
			p.ErrorPage(rw, http.StatusInternalServerError,
				"Internal Error", "Internal Error")
		} else {
			clog.Info("should use user account.", user.UserInfo.UserAccount)

			session := &SessionState{User: user.UserInfo.UserAccount}
			p.SaveSession(rw, req, session)

			// http.SetCookie(rw, p.MakeSessionCookie(req, "skjdhwiuehassadwelqjfwefhask", time.Minute*30, time.Now()))
			http.Redirect(rw, req, "/app/#/console/project/chaizs/dashboard", 302)
		}
	} else {
		clog.Debug("token is empty")
		http.Redirect(rw, req, p.SsoStartPath, 302)
	}
}

func (p *SsoProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *SessionState) error {
	value, err := p.CookieForSession(s, p.CookieCipher)
	if err != nil {
		return err
	}
	p.SetSessionCookie(rw, req, value)
	return nil
}

// CookieForSession serializes a session state for storage in a cookie
func (p *SsoProxy) CookieForSession(s *SessionState, c *cookie.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}
func (p *SsoProxy) SetSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, p.MakeSessionCookie(req, val, p.CookieExpire, time.Now()))
}

func (p *SsoProxy) MakeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	if value != "" {
		value = cookie.SignedValue(fmt.Sprintf("%s%s", p.CookieSeed, req.Host), p.CookieName, value, now)
		if len(value) > 4096 {
			// Cookies cannot be larger than 4kb
			clog.Warnf("WARNING - Cookie Size: %d bytes", len(value))
		}
	}
	return p.makeCookie(req, p.CookieName, value, expiration, now)
}

func (p *SsoProxy) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	// if p.CookieDomain != "" {
	// 	if !strings.HasSuffix(domain, p.CookieDomain) {
	// 		log.Printf("Warning: request host is %q but using configured cookie domain of %q", domain, p.CookieDomain)
	// 	}
	// 	domain = p.CookieDomain
	// }

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   false,
		Expires:  now.Add(expiration),
	}
}

type userinfo struct {
	Username    string `json:"user_name"`
	UserAccount string `json:"user_account"`
	LoginTime   string `json:"login_time"`
	Token       string `json:"token"`
	Status      string `json:"status"`
	Phone       string `json:"phone_num"`
	JobTitle    string `json:"job_title"`
	UserID      string `json:"user_id"`
	StatCode    string `state_code`
}
type User struct {
	Result    string   `json:"result"`
	ResultMsg string   `json:"returnMsg"`
	UserID    string   `json:"userId"`
	UserInfo  userinfo `json:"userInfo"`
}

func (p *SsoProxy) Redeem(token string) (u *User, err error) {
	if token == "" {
		err = errors.New("missing token")
		return
	}

	redeemUrl := "http://10.1.235.171:12005/dmc/ssoAuth?token=" + token
	var req *http.Request
	req, err = http.NewRequest("GET", redeemUrl, nil)

	if err != nil {
		return nil, err
	}

	transCfg := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transCfg,
		// Timeout:   timeout,
	}

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	// clog.Info(string(body))
	user := &User{}
	if err = json.Unmarshal(body, user); err != nil {
		clog.Error(err)
	}
	return user, err
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
}

func (p *SsoProxy) Authenticate(rw http.ResponseWriter, req *http.Request) int {
	// clog.Error("TODO checking session/token, make/clear session etc.")

	clog.Error("TODO if no session, return forbidden to start sso.")

	return http.StatusAccepted
}

func (p *SsoProxy) SsoStart(rw http.ResponseWriter, req *http.Request) {
	// clog.Error("TODO 302 to sso site.")
	// authURL := "http://10.1.235.171:12005/dmc/dev/module/login/login.html?goto=http%3A%2F%2Flocalhost%3A9090%2Fapp%2F%23%2Fconsole%2Fproject%2Fchaizs%2Fdashboard"
	authURL := "http://10.1.235.171:12005/dmc/dev/module/login/login.html?goto=http://localhost:9090/auth"
	// clog.Debugf("%#v", req.URL)

	http.Redirect(rw, req, authURL, 302)
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
