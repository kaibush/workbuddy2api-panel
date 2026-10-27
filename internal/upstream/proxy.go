// proxy.go 出站粘性代理。
//
// Resin 这类代理用用户名区分出口：同一用户名固定出口，不同用户名互不复用连接。
// 模板（默认）：
//
//	http://{平台名称}.{account}:<token>@207.58.173.239:2260
//
// 账号标识放进用户名，密码就是 token。
// 因此 http.Transport 会按完整代理 URL 分连接池——同账号复用，账号之间不共用。
// 没带账号的请求（更新检查、models.dev）不打标，继续直连。
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// DefaultProxyURL 面板和配置缺省使用的 Resin 粘性模板。
// 占位符：{平台名称}/{platform}、{account}、<token>/{token}。
const DefaultProxyURL = "http://{平台名称}.{account}:<token>@207.58.173.239:2260"

// stickyAccountHeader 只在进程内把账号交给传输层，发出去之前会删掉。
// 不能用请求 context 从各调用点往下传：头构造函数拿不到替换后的 *Request。
const stickyAccountHeader = "X-WB-Sticky-Account"

type stickyAccountKey struct{}

// ProxyConfig 面板/配置文件里的出站代理。Enabled 为 false 时账号请求直连。
type ProxyConfig struct {
	Enabled  bool
	Platform string
	Token    string
	URL      string
}

type proxySettings struct {
	Enabled  bool
	Platform string
	Token    string
	URL      string
}

// stickyProxy 包在共享 *http.Transport 外。HTTP 与 ChatHTTP 仍共用这一层，
// 底下的连接池也还是同一个。
type stickyProxy struct {
	base *http.Transport
	cfg  atomic.Pointer[proxySettings]
}

func newProxyRT() *stickyProxy {
	p := &stickyProxy{}
	p.base = newTransport()
	p.base.Proxy = p.proxyFor
	return p
}

func (p *stickyProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil {
		if account := req.Header.Get(stickyAccountHeader); account != "" {
			// 换一份 Header，避免删掉调用方还拿着的那张表。
			hdr := req.Header.Clone()
			hdr.Del(stickyAccountHeader)
			ctx := context.WithValue(req.Context(), stickyAccountKey{}, account)
			req = req.WithContext(ctx)
			req.Header = hdr
		}
	}
	return p.base.RoundTrip(req)
}

func (p *stickyProxy) CloseIdleConnections() {
	if p != nil && p.base != nil {
		p.base.CloseIdleConnections()
	}
}

func (p *stickyProxy) proxyFor(req *http.Request) (*url.URL, error) {
	s := p.cfg.Load()
	if s == nil || !s.Enabled || req == nil {
		return nil, nil
	}
	account, _ := req.Context().Value(stickyAccountKey{}).(string)
	if account == "" {
		return nil, nil
	}
	return s.urlFor(account)
}

func (p *stickyProxy) set(cfg ProxyConfig) {
	next := normalizeProxySettings(cfg)
	prev := p.cfg.Swap(next)
	if proxySettingsEqual(prev, next) {
		return
	}
	if prev != nil && p.base != nil {
		// 代理身份变了就丢掉旧池，避免短时间内还复用上一个出口。
		p.base.CloseIdleConnections()
	}
	switch {
	case next.Enabled:
		log.Printf("出站代理已启用（平台=%s，按账号粘性=%v）", next.Platform, strings.Contains(next.URL, "{account}"))
	case prev != nil && prev.Enabled:
		log.Printf("出站代理已关闭")
	}
}

func proxySettingsEqual(a, b *proxySettings) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func normalizeProxySettings(cfg ProxyConfig) *proxySettings {
	s := &proxySettings{
		Enabled:  cfg.Enabled,
		Platform: strings.TrimSpace(cfg.Platform),
		Token:    strings.TrimSpace(cfg.Token),
		URL:      strings.TrimSpace(cfg.URL),
	}
	if s.URL == "" {
		s.URL = DefaultProxyURL
	}
	return s
}

// SetProxy 热更新出站代理。未启用、或请求没带账号时保持直连。
func (c *Client) SetProxy(cfg ProxyConfig) {
	if c == nil || c.proxy == nil {
		return
	}
	c.proxy.set(cfg)
}

// HTTPTransport 取出共享的 *http.Transport。
// 生产路径外面包了 stickyProxy，DNS 与首字节超时仍要改到内层。
func HTTPTransport(rt http.RoundTripper) *http.Transport {
	switch t := rt.(type) {
	case *http.Transport:
		return t
	case *stickyProxy:
		if t != nil {
			return t.base
		}
	}
	return nil
}

// ValidateProxy 在启用时检查模板能拼出合法代理 URL。关闭时不强制凭据。
func ValidateProxy(cfg ProxyConfig) error {
	s := normalizeProxySettings(cfg)
	if !s.Enabled {
		return nil
	}
	user, pass, host, err := proxyTemplateParts(s.URL)
	if err != nil {
		return err
	}
	joined := user + "\n" + pass + "\n" + host
	if strings.Contains(joined, "{平台名称}") || strings.Contains(joined, "{platform}") {
		if s.Platform == "" {
			return errors.New("proxy.platform 为空（URL 含平台占位符）")
		}
	}
	if strings.Contains(joined, "<token>") || strings.Contains(joined, "{token}") {
		if s.Token == "" {
			return errors.New("proxy.token 为空（URL 含 token 占位符）")
		}
	}
	if _, err := s.urlFor("account"); err != nil {
		return err
	}
	return nil
}

func (s *proxySettings) urlFor(account string) (*url.URL, error) {
	scheme, user, pass, host, hasUser, hasPass, err := splitProxyTemplate(s.URL)
	if err != nil {
		return nil, err
	}
	account = sanitizeStickyAccount(account)
	user = applyProxyPlaceholders(user, s.Platform, s.Token, account)
	pass = applyProxyPlaceholders(pass, s.Platform, s.Token, account)
	host = applyProxyPlaceholders(host, s.Platform, s.Token, account)
	if host == "" {
		return nil, errors.New("proxy: host 为空")
	}
	if strings.Contains(s.URL, "{account}") && account == "" {
		return nil, errors.New("proxy: 账号标识为空")
	}
	u := &url.URL{Scheme: scheme, Host: host}
	if hasUser {
		switch {
		case hasPass:
			u.User = url.UserPassword(user, pass)
		case user != "":
			u.User = url.User(user)
		}
	}
	return u, nil
}

func proxyTemplateParts(raw string) (user, pass, host string, err error) {
	_, user, pass, host, _, _, err = splitProxyTemplate(raw)
	return user, pass, host, err
}

func splitProxyTemplate(raw string) (scheme, user, pass, host string, hasUser, hasPass bool, err error) {
	raw = strings.TrimSpace(raw)
	i := strings.Index(raw, "://")
	if i <= 0 {
		return "", "", "", "", false, false, errors.New("proxy.url 缺少 scheme")
	}
	scheme = strings.ToLower(raw[:i])
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", "", "", "", false, false, errors.New("proxy.url 只支持 http、https、socks5、socks5h")
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	at := strings.LastIndex(rest, "@")
	host = rest
	if at >= 0 {
		hasUser = true
		userinfo := rest[:at]
		host = rest[at+1:]
		if colon := strings.Index(userinfo, ":"); colon >= 0 {
			hasPass = true
			user = userinfo[:colon]
			pass = userinfo[colon+1:]
		} else {
			user = userinfo
		}
	}
	if host == "" {
		return "", "", "", "", false, false, errors.New("proxy.url 缺少 host")
	}
	return scheme, user, pass, host, hasUser, hasPass, nil
}

func applyProxyPlaceholders(s, platform, token, account string) string {
	return strings.NewReplacer(
		"{平台名称}", platform,
		"{platform}", platform,
		"{account}", account,
		"<token>", token,
		"{token}", token,
	).Replace(s)
}

// stampStickyAccount 给带账号的出站请求打内部头。传输层读完即删，不会送到上游或代理。
func (c *Client) stampStickyAccount(req *http.Request, a *auth.Auth) {
	if c == nil || req == nil {
		return
	}
	id := stickyAccountID(a)
	if id == "" {
		return
	}
	req.Header.Set(stickyAccountHeader, id)
}

func stickyAccountID(a *auth.Auth) string {
	if a == nil {
		return ""
	}
	raw := strings.TrimSpace(a.UID)
	if raw == "" && a.FilePath != "" {
		base := filepath.Base(a.FilePath)
		raw = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if id := sanitizeStickyAccount(raw); id != "" {
		return id
	}
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return "a" + hex.EncodeToString(sum[:6])
}

func sanitizeStickyAccount(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
