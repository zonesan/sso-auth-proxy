# sso-auth-proxy

## About

sso-proxy will serve on address 0.0.0.0:9090. IPv6 not supported.

## Usage example

```bash
# required
export SSO_LOGIN_BASE_URL="http://10.1.235.171:12005/dmc/dev/module/login/login.html?goto="
export SSO_REDEEM_BASE_URL="http://10.1.235.171:12005/dmc/ssoAuth?token="
export SSO_UPSTREAM_URL="localhost:18080"
# optional
export SSO_REDIRECT_URI="/app/#/console/project/%s/dashboard"
export SSO_PROXY_PREFIX="/sso/abc"
./sso-proxy
```