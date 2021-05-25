package authreq

import "k8s.io/ingress-nginx/internal/sets"

// Config returns external authentication configuration for an Ingress rule
// +k8s:deepcopy-gen=true
type Config struct {
	URL string `json:"url"`
	// Host contains the hostname defined in the URL
	Host                   string            `json:"host"`
	SigninURL              string            `json:"signinUrl"`
	SigninURLRedirectParam string            `json:"signinUrlRedirectParam,omitempty"`
	Method                 string            `json:"method"`
	ResponseHeaders        []string          `json:"responseHeaders,omitempty"`
	RequestRedirect        string            `json:"requestRedirect"`
	AuthSnippet            string            `json:"authSnippet"`
	AuthCacheKey           string            `json:"authCacheKey"`
	AuthCacheDuration      []string          `json:"authCacheDuration"`
	ProxySetHeaders        map[string]string `json:"proxySetHeaders,omitempty"`
}

// Equal tests for equality between two Config types
func (e1 *Config) Equal(e2 *Config) bool {
	if e1 == e2 {
		return true
	}
	if e1 == nil || e2 == nil {
		return false
	}
	if e1.URL != e2.URL {
		return false
	}
	if e1.Host != e2.Host {
		return false
	}
	if e1.SigninURL != e2.SigninURL {
		return false
	}
	if e1.SigninURLRedirectParam != e2.SigninURLRedirectParam {
		return false
	}
	if e1.Method != e2.Method {
		return false
	}

	match := sets.StringElementsMatch(e1.ResponseHeaders, e2.ResponseHeaders)
	if !match {
		return false
	}

	if e1.RequestRedirect != e2.RequestRedirect {
		return false
	}
	if e1.AuthSnippet != e2.AuthSnippet {
		return false
	}

	if e1.AuthCacheKey != e2.AuthCacheKey {
		return false
	}

	return sets.StringElementsMatch(e1.AuthCacheDuration, e2.AuthCacheDuration)
}
