package upstream

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

func TestStickyProxyURLResinTemplate(t *testing.T) {
	s := normalizeProxySettings(ProxyConfig{
		Enabled:  true,
		Platform: "resin",
		Token:    "sek",
		URL:      DefaultProxyURL,
	})
	u, err := s.urlFor("acc_1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "207.58.173.239:2260" {
		t.Fatalf("url=%s", u.Redacted())
	}
	if got := u.User.Username(); got != "resin.acc_1" {
		t.Fatalf("user=%q", got)
	}
	pass, ok := u.User.Password()
	if !ok || pass != "sek" {
		t.Fatalf("pass=%q ok=%v，密码应等于 token", pass, ok)
	}
	again, err := s.urlFor("acc_1")
	if err != nil {
		t.Fatal(err)
	}
	if again.String() != u.String() {
		t.Fatalf("同账号代理 URL 不稳定\n%s\n%s", u, again)
	}
	other, err := s.urlFor("acc_2")
	if err != nil {
		t.Fatal(err)
	}
	if other.String() == u.String() {
		t.Fatal("不同账号不应共用同一个代理 URL")
	}
}

func TestStickyProxyTokenSpecialChars(t *testing.T) {
	s := normalizeProxySettings(ProxyConfig{
		Enabled:  true,
		Platform: "plat",
		Token:    "p@ss w/rd?",
		URL:      "http://{platform}.{account}:{token}@10.1.2.3:2260",
	})
	u, err := s.urlFor("acc")
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := u.User.Password()
	if pass != "p@ss w/rd?" {
		t.Fatalf("pass=%q", pass)
	}
	parsed, err := url.Parse(u.String())
	if err != nil {
		t.Fatal(err)
	}
	pass2, _ := parsed.User.Password()
	if pass2 != pass || parsed.User.Username() != "plat.acc" {
		t.Fatalf("round trip user=%q pass=%q", parsed.User.Username(), pass2)
	}
}

func TestStickyProxyStaticURLShared(t *testing.T) {
	s := normalizeProxySettings(ProxyConfig{Enabled: true, URL: "http://u:p@127.0.0.1:8080"})
	a, err := s.urlFor("one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.urlFor("two")
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatalf("无占位符时应共用代理：%s vs %s", a, b)
	}
	if err := ValidateProxy(ProxyConfig{Enabled: true, URL: "http://u:p@127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProxyRequiresCredentials(t *testing.T) {
	if err := ValidateProxy(ProxyConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxy(ProxyConfig{Enabled: true, Platform: "resin", URL: DefaultProxyURL}); err == nil {
		t.Fatal("缺 token 应失败")
	}
	if err := ValidateProxy(ProxyConfig{Enabled: true, Token: "sek", URL: DefaultProxyURL}); err == nil {
		t.Fatal("缺平台名应失败")
	}
	if err := ValidateProxy(ProxyConfig{Enabled: true, URL: "ftp://example"}); err == nil {
		t.Fatal("非法 scheme 应失败")
	}
}

func TestStickyAccountID(t *testing.T) {
	if got := stickyAccountID(&auth.Auth{UID: "ab.cd/ef"}); got != "abcdef" {
		t.Fatalf("sanitize=%q", got)
	}
	if got := stickyAccountID(&auth.Auth{FilePath: "/data/auths/user-1.json"}); got != "user-1" {
		t.Fatalf("file=%q", got)
	}
	if stickyAccountID(nil) != "" || stickyAccountID(&auth.Auth{}) != "" {
		t.Fatal("空账号应直连")
	}
	a := stickyAccountID(&auth.Auth{UID: "!!!"})
	b := stickyAccountID(&auth.Auth{UID: "!!!"})
	if a == "" || a != b {
		t.Fatalf("异常 UID 应稳定：%q %q", a, b)
	}
	if stickyAccountID(&auth.Auth{UID: "???"}) == a {
		t.Fatal("不同异常 UID 不应撞车")
	}
}

func TestProxyRoundTripStripsHeaderAndSelectsAccount(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(stickyAccountHeader); v != "" {
			mu.Lock()
			leaked = append(leaked, v)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New()
	c.SetProxy(ProxyConfig{Enabled: true, Platform: "resin", Token: "sek", URL: DefaultProxyURL})
	tr := HTTPTransport(c.HTTP.Transport)
	if tr == nil {
		t.Fatal("内层 Transport 丢失")
	}
	var chosen []*url.URL
	orig := tr.Proxy
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		u, err := orig(r)
		chosen = append(chosen, u)
		return nil, err
	}

	do := func(a *auth.Auth) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.stampStickyAccount(req, a)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	do(&auth.Auth{UID: "acc_1"})
	do(&auth.Auth{UID: "acc_1"})
	do(&auth.Auth{UID: "acc_2"})
	do(nil)

	mu.Lock()
	if len(leaked) != 0 {
		t.Fatalf("粘性头泄漏到上游：%q", leaked)
	}
	mu.Unlock()
	if len(chosen) != 4 {
		t.Fatalf("proxy 调用次数=%d", len(chosen))
	}
	if chosen[0] == nil || chosen[0].String() != chosen[1].String() {
		t.Fatal("同账号应选同一个代理")
	}
	if chosen[2] == nil || chosen[2].String() == chosen[0].String() {
		t.Fatal("不同账号应选不同代理")
	}
	if chosen[3] != nil {
		t.Fatalf("无账号应直连，got %s", chosen[3].Redacted())
	}
	pass, _ := chosen[0].User.Password()
	if chosen[0].User.Username() != "resin.acc_1" || pass != "sek" {
		t.Fatalf("user=%q pass=%q", chosen[0].User.Username(), pass)
	}
}

func TestProxyDisabledStaysDirectAndStripsHeader(t *testing.T) {
	var leaked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get(stickyAccountHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New()
	c.SetProxy(ProxyConfig{Enabled: true, Platform: "resin", Token: "sek"})
	c.SetProxy(ProxyConfig{Enabled: false, Platform: "resin", Token: "sek"})
	tr := HTTPTransport(c.HTTP.Transport)
	var got *url.URL
	called := false
	orig := tr.Proxy
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		called = true
		u, err := orig(r)
		got = u
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	c.stampStickyAccount(req, &auth.Auth{UID: "acc_1"})
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !called || got != nil {
		t.Fatalf("关闭代理后应直连 called=%v url=%v", called, got)
	}
	if leaked != "" {
		t.Fatalf("关闭后仍泄漏粘性头：%q", leaked)
	}
}
