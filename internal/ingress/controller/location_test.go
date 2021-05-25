package controller

import (
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/ingress-nginx/internal/ingress"
	"k8s.io/ingress-nginx/internal/ingress/annotations"
	"k8s.io/ingress-nginx/internal/ingress/annotations/auth"
	"k8s.io/ingress-nginx/internal/ingress/annotations/authreq"
	"k8s.io/ingress-nginx/internal/ingress/annotations/authtls"
	"k8s.io/ingress-nginx/internal/ingress/annotations/canary"
	"k8s.io/ingress-nginx/internal/ingress/annotations/connection"
	"k8s.io/ingress-nginx/internal/ingress/annotations/cors"
	"k8s.io/ingress-nginx/internal/ingress/annotations/fastcgi"
	"k8s.io/ingress-nginx/internal/ingress/annotations/influxdb"
	"k8s.io/ingress-nginx/internal/ingress/annotations/ipwhitelist"
	"k8s.io/ingress-nginx/internal/ingress/annotations/log"
	"k8s.io/ingress-nginx/internal/ingress/annotations/mirror"
	"k8s.io/ingress-nginx/internal/ingress/annotations/modsecurity"
	"k8s.io/ingress-nginx/internal/ingress/annotations/opentracing"
	"k8s.io/ingress-nginx/internal/ingress/annotations/proxy"
	"k8s.io/ingress-nginx/internal/ingress/annotations/proxyssl"
	"k8s.io/ingress-nginx/internal/ingress/annotations/ratelimit"
	redirectannotation "k8s.io/ingress-nginx/internal/ingress/annotations/redirect"
	"k8s.io/ingress-nginx/internal/ingress/annotations/rewrite"
	"k8s.io/ingress-nginx/internal/ingress/annotations/secureupstream"
	"k8s.io/ingress-nginx/internal/ingress/annotations/sessionaffinity"
	"k8s.io/ingress-nginx/internal/ingress/annotations/sslcipher"
	"k8s.io/ingress-nginx/internal/ingress/annotations/upstreamhashby"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

var result []*ingress.Location

func BenchmarkUpdateServerLocations(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		locations := make([]*ingress.Location, 1000)
		for i := 0; i < 1000; i++ {
			locations[i] = createLocation()
		}
		b.StartTimer()
		updateServerLocations(locations)
	}
}

func createLocation() *ingress.Location {
	return &ingress.Location{
		Path:         "",
		PathType:     &pathTypeExact,
		IsDefBackend: false,
		Ingress: &ingress.Ingress{
			Ingress: networking.Ingress{
				TypeMeta: metav1.TypeMeta{
					Kind:       "",
					APIVersion: "",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "",
					GenerateName:    "",
					Namespace:       "",
					SelfLink:        "",
					UID:             "",
					ResourceVersion: "",
					Generation:      0,
					CreationTimestamp: metav1.Time{
						Time: time.Time{},
					},
					DeletionTimestamp: &metav1.Time{
						Time: time.Time{},
					},
					DeletionGracePeriodSeconds: nil,
					Labels:                     nil,
					Annotations:                nil,
					OwnerReferences:            nil,
					Finalizers:                 nil,
					ClusterName:                "",
					ManagedFields:              nil,
				},
				Spec: networking.IngressSpec{
					IngressClassName: nil,
					Backend: &networking.IngressBackend{
						ServiceName: "",
						ServicePort: intstr.IntOrString{
							Type:   0,
							IntVal: 0,
							StrVal: "",
						},
						Resource: &v1.TypedLocalObjectReference{
							APIGroup: nil,
							Kind:     "",
							Name:     "",
						},
					},
					TLS:   nil,
					Rules: nil,
				},
				Status: networking.IngressStatus{
					LoadBalancer: v1.LoadBalancerStatus{
						Ingress: []v1.LoadBalancerIngress{
							{
								IP:       "",
								Hostname: "",
								Ports: []v1.PortStatus{
									{
										Port:     0,
										Protocol: "",
										Error:    nil,
									}}}},
					},
				},
			},
			ParsedAnnotations: &annotations.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "",
					GenerateName:    "",
					Namespace:       "",
					SelfLink:        "",
					UID:             "",
					ResourceVersion: "",
					Generation:      0,
					CreationTimestamp: metav1.Time{
						Time: time.Time{},
					},
					DeletionTimestamp: &metav1.Time{
						Time: time.Time{},
					},
					DeletionGracePeriodSeconds: nil,
					Labels:                     map[string]string{},
					Annotations:                map[string]string{},
					OwnerReferences:            nil,
					Finalizers:                 nil,
					ClusterName:                "",
					ManagedFields:              nil,
				},
				BackendProtocol: "",
				Aliases:         []string{},
				BasicDigestAuth: auth.Config{
					Type:       "",
					Realm:      "",
					File:       "",
					Secured:    false,
					FileSHA:    "",
					Secret:     "",
					SecretType: "",
				},
				Canary: canary.Config{
					Enabled:       false,
					Weight:        0,
					Header:        "",
					HeaderValue:   "",
					HeaderPattern: "",
					Cookie:        "",
				},
				CertificateAuth: authtls.Config{
					AuthSSLCert: resolver.AuthSSLCert{
						Secret:      "",
						CAFileName:  "",
						CASHA:       "",
						CRLFileName: "",
						CRLSHA:      "",
						PemFileName: "",
					},
					VerifyClient:       "",
					ValidationDepth:    0,
					ErrorPage:          "",
					PassCertToUpstream: false,
					AuthTLSError:       "",
				},
				ClientBodyBufferSize: "",
				ConfigurationSnippet: "",
				Connection: connection.Config{
					Header:  "",
					Enabled: false,
				},
				CorsConfig: cors.Config{
					CorsEnabled:          false,
					CorsAllowOrigin:      "",
					CorsAllowMethods:     "",
					CorsAllowHeaders:     "",
					CorsAllowCredentials: false,
					CorsExposeHeaders:    "",
					CorsMaxAge:           0,
				},
				CustomHTTPErrors: nil,
				DefaultBackend: &v1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "",
						APIVersion: "",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            "",
						GenerateName:    "",
						Namespace:       "",
						SelfLink:        "",
						UID:             "",
						ResourceVersion: "",
						Generation:      0,
						CreationTimestamp: metav1.Time{
							Time: time.Time{},
						},
						DeletionTimestamp: &metav1.Time{
							Time: time.Time{},
						},
						DeletionGracePeriodSeconds: nil,
						Labels:                     map[string]string{},
						Annotations:                map[string]string{},
						OwnerReferences:            nil,
						Finalizers:                 nil,
						ClusterName:                "",
						ManagedFields:              nil,
					},
					Spec: v1.ServiceSpec{
						Ports:                    nil,
						Selector:                 nil,
						ClusterIP:                "",
						ClusterIPs:               nil,
						Type:                     "",
						ExternalIPs:              nil,
						SessionAffinity:          "",
						LoadBalancerIP:           "",
						LoadBalancerSourceRanges: nil,
						ExternalName:             "",
						ExternalTrafficPolicy:    "",
						HealthCheckNodePort:      0,
						PublishNotReadyAddresses: false,
						SessionAffinityConfig: &v1.SessionAffinityConfig{
							ClientIP: &v1.ClientIPConfig{
								TimeoutSeconds: nil,
							},
						},
						TopologyKeys:                  nil,
						IPFamilies:                    nil,
						IPFamilyPolicy:                nil,
						AllocateLoadBalancerNodePorts: nil,
					},
					Status: v1.ServiceStatus{
						LoadBalancer: v1.LoadBalancerStatus{
							Ingress: nil,
						},
						Conditions: nil,
					},
				},
				FastCGI: fastcgi.Config{
					Index:  "",
					Params: nil,
				},
				Denied: nil,
				ExternalAuth: authreq.Config{
					URL:                    "",
					Host:                   "",
					SigninURL:              "",
					SigninURLRedirectParam: "",
					Method:                 "",
					ResponseHeaders:        nil,
					RequestRedirect:        "",
					AuthSnippet:            "",
					AuthCacheKey:           "",
					AuthCacheDuration:      nil,
					ProxySetHeaders:        nil,
				},
				EnableGlobalAuth: false,
				HTTP2PushPreload: false,
				Opentracing: opentracing.Config{
					Enabled: false,
					Set:     false,
				},
				Proxy: proxy.Config{
					BodySize:             "",
					ConnectTimeout:       0,
					SendTimeout:          0,
					ReadTimeout:          0,
					BuffersNumber:        0,
					BufferSize:           "",
					CookieDomain:         "",
					CookiePath:           "",
					NextUpstream:         "",
					NextUpstreamTimeout:  0,
					NextUpstreamTries:    0,
					ProxyRedirectFrom:    "",
					ProxyRedirectTo:      "",
					RequestBuffering:     "",
					ProxyBuffering:       "",
					ProxyHTTPVersion:     "",
					ProxyMaxTempFileSize: "",
				},
				ProxySSL: proxyssl.Config{
					AuthSSLCert: resolver.AuthSSLCert{
						Secret:      "",
						CAFileName:  "",
						CASHA:       "",
						CRLFileName: "",
						CRLSHA:      "",
						PemFileName: "",
					},
					Ciphers:            "",
					Protocols:          "",
					ProxySSLName:       "",
					Verify:             "",
					VerifyDepth:        0,
					ProxySSLServerName: "",
				},
				RateLimit: ratelimit.Config{
					Connections: ratelimit.Zone{
						Name:       "",
						Limit:      0,
						Burst:      0,
						SharedSize: 0,
					},
					RPS: ratelimit.Zone{
						Name:       "",
						Limit:      0,
						Burst:      0,
						SharedSize: 0,
					},
					RPM: ratelimit.Zone{
						Name:       "",
						Limit:      0,
						Burst:      0,
						SharedSize: 0,
					},
					LimitRate:      0,
					LimitRateAfter: 0,
					Name:           "",
					ID:             "",
					Whitelist:      nil,
				},
				Redirect: redirectannotation.Config{
					URL:       "",
					Code:      0,
					FromToWWW: false,
				},
				Rewrite: rewrite.Config{
					Target:           "",
					SSLRedirect:      false,
					ForceSSLRedirect: false,
					AppRoot:          "",
					UseRegex:         false,
				},
				Satisfy: "",
				SecureUpstream: secureupstream.Config{
					CACert: resolver.AuthSSLCert{
						Secret:      "",
						CAFileName:  "",
						CASHA:       "",
						CRLFileName: "",
						CRLSHA:      "",
						PemFileName: "",
					},
				},
				ServerSnippet:   "",
				ServiceUpstream: false,
				SessionAffinity: sessionaffinity.Config{
					Type: "",
					Mode: "",
					Cookie: sessionaffinity.Cookie{
						Name:                    "",
						Expires:                 "",
						MaxAge:                  "",
						Path:                    "",
						ChangeOnFailure:         false,
						SameSite:                "",
						ConditionalSameSiteNone: false,
					},
				},
				SSLPassthrough:     false,
				UsePortInRedirects: false,
				UpstreamHashBy: upstreamhashby.Config{
					UpstreamHashBy:           "",
					UpstreamHashBySubset:     false,
					UpstreamHashBySubsetSize: 0,
				},
				LoadBalancing: "",
				UpstreamVhost: "",
				Whitelist: ipwhitelist.SourceRange{
					CIDR: nil,
				},
				XForwardedPrefix: "",
				SSLCipher: sslcipher.Config{
					SSLCiphers:             "",
					SSLPreferServerCiphers: "",
				},
				Logs: log.Config{
					Access:  false,
					Rewrite: false,
				},
				InfluxDB: influxdb.Config{
					InfluxDBEnabled:     false,
					InfluxDBMeasurement: "",
					InfluxDBPort:        "",
					InfluxDBHost:        "",
					InfluxDBServerName:  "",
				},
				ModSecurity: modsecurity.Config{
					Enable:        false,
					EnableSet:     false,
					OWASPRules:    false,
					TransactionID: "",
					Snippet:       "",
				},
				Mirror: mirror.Config{
					Source:      "",
					RequestBody: "",
					Target:      "",
				},
			},
		},
		IngressPath: "",
		Backend:     "",
		Service: &v1.Service{
			TypeMeta: metav1.TypeMeta{
				Kind:       "",
				APIVersion: "",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "",
				GenerateName:    "",
				Namespace:       "",
				SelfLink:        "",
				UID:             "",
				ResourceVersion: "",
				Generation:      0,
				CreationTimestamp: metav1.Time{
					Time: time.Time{},
				},
				DeletionTimestamp: &metav1.Time{
					Time: time.Time{},
				},
				DeletionGracePeriodSeconds: nil,
				Labels:                     nil,
				Annotations:                nil,
				OwnerReferences:            nil,
				Finalizers:                 nil,
				ClusterName:                "",
				ManagedFields:              nil,
			},
			Spec: v1.ServiceSpec{
				Ports:                    nil,
				Selector:                 nil,
				ClusterIP:                "",
				ClusterIPs:               nil,
				Type:                     "",
				ExternalIPs:              nil,
				SessionAffinity:          "",
				LoadBalancerIP:           "",
				LoadBalancerSourceRanges: nil,
				ExternalName:             "",
				ExternalTrafficPolicy:    "",
				HealthCheckNodePort:      0,
				PublishNotReadyAddresses: false,
				SessionAffinityConfig: &v1.SessionAffinityConfig{
					ClientIP: &v1.ClientIPConfig{
						TimeoutSeconds: nil,
					},
				},
				TopologyKeys:                  nil,
				IPFamilies:                    nil,
				IPFamilyPolicy:                nil,
				AllocateLoadBalancerNodePorts: nil,
			},
			Status: v1.ServiceStatus{
				LoadBalancer: v1.LoadBalancerStatus{
					Ingress: nil,
				},
				Conditions: nil,
			},
		},
		Port: intstr.IntOrString{
			Type:   0,
			IntVal: 0,
			StrVal: "",
		},
		UpstreamVhost: "",
		BasicDigestAuth: auth.Config{
			Type:       "",
			Realm:      "",
			File:       "",
			Secured:    false,
			FileSHA:    "",
			Secret:     "",
			SecretType: "",
		},
		Denied: nil,
		CorsConfig: cors.Config{
			CorsEnabled:          false,
			CorsAllowOrigin:      "",
			CorsAllowMethods:     "",
			CorsAllowHeaders:     "",
			CorsAllowCredentials: false,
			CorsExposeHeaders:    "",
			CorsMaxAge:           0,
		},
		ExternalAuth: authreq.Config{
			URL:                    "",
			Host:                   "",
			SigninURL:              "",
			SigninURLRedirectParam: "",
			Method:                 "",
			ResponseHeaders:        nil,
			RequestRedirect:        "",
			AuthSnippet:            "",
			AuthCacheKey:           "",
			AuthCacheDuration:      nil,
			ProxySetHeaders:        nil,
		},
		EnableGlobalAuth: false,
		HTTP2PushPreload: false,
		RateLimit: ratelimit.Config{
			Connections: ratelimit.Zone{
				Name:       "",
				Limit:      0,
				Burst:      0,
				SharedSize: 0,
			},
			RPS: ratelimit.Zone{
				Name:       "",
				Limit:      0,
				Burst:      0,
				SharedSize: 0,
			},
			RPM: ratelimit.Zone{
				Name:       "",
				Limit:      0,
				Burst:      0,
				SharedSize: 0,
			},
			LimitRate:      0,
			LimitRateAfter: 0,
			Name:           "",
			ID:             "",
			Whitelist:      nil,
		},
		Redirect: redirectannotation.Config{
			URL:       "",
			Code:      0,
			FromToWWW: false,
		},
		Rewrite: rewrite.Config{
			Target:           "",
			SSLRedirect:      false,
			ForceSSLRedirect: false,
			AppRoot:          "",
			UseRegex:         false,
		},
		Whitelist: ipwhitelist.SourceRange{
			CIDR: nil,
		},
		Proxy: proxy.Config{
			BodySize:             "",
			ConnectTimeout:       0,
			SendTimeout:          0,
			ReadTimeout:          0,
			BuffersNumber:        0,
			BufferSize:           "",
			CookieDomain:         "",
			CookiePath:           "",
			NextUpstream:         "",
			NextUpstreamTimeout:  0,
			NextUpstreamTries:    0,
			ProxyRedirectFrom:    "",
			ProxyRedirectTo:      "",
			RequestBuffering:     "",
			ProxyBuffering:       "",
			ProxyHTTPVersion:     "",
			ProxyMaxTempFileSize: "",
		},
		ProxySSL: proxyssl.Config{
			AuthSSLCert: resolver.AuthSSLCert{
				Secret:      "",
				CAFileName:  "",
				CASHA:       "",
				CRLFileName: "",
				CRLSHA:      "",
				PemFileName: "",
			},
			Ciphers:            "",
			Protocols:          "",
			ProxySSLName:       "",
			Verify:             "",
			VerifyDepth:        0,
			ProxySSLServerName: "",
		},
		UsePortInRedirects:   false,
		ConfigurationSnippet: "",
		Connection: connection.Config{
			Header:  "",
			Enabled: false,
		},
		ClientBodyBufferSize: "",
		DefaultBackend: &v1.Service{
			TypeMeta: metav1.TypeMeta{
				Kind:       "",
				APIVersion: "",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "",
				GenerateName:    "",
				Namespace:       "",
				SelfLink:        "",
				UID:             "",
				ResourceVersion: "",
				Generation:      0,
				CreationTimestamp: metav1.Time{
					Time: time.Time{},
				},
				DeletionTimestamp: &metav1.Time{
					Time: time.Time{},
				},
				DeletionGracePeriodSeconds: nil,
				Labels:                     map[string]string{},
				Annotations:                map[string]string{},
				OwnerReferences:            nil,
				Finalizers:                 nil,
				ClusterName:                "",
				ManagedFields:              nil,
			},
			Spec: v1.ServiceSpec{
				Ports:                    nil,
				Selector:                 nil,
				ClusterIP:                "",
				ClusterIPs:               nil,
				Type:                     "",
				ExternalIPs:              nil,
				SessionAffinity:          "",
				LoadBalancerIP:           "",
				LoadBalancerSourceRanges: nil,
				ExternalName:             "",
				ExternalTrafficPolicy:    "",
				HealthCheckNodePort:      0,
				PublishNotReadyAddresses: false,
				SessionAffinityConfig: &v1.SessionAffinityConfig{
					ClientIP: &v1.ClientIPConfig{
						TimeoutSeconds: nil,
					},
				},
				TopologyKeys:                  nil,
				IPFamilies:                    nil,
				IPFamilyPolicy:                nil,
				AllocateLoadBalancerNodePorts: nil,
			},
			Status: v1.ServiceStatus{
				LoadBalancer: v1.LoadBalancerStatus{
					Ingress: nil,
				},
				Conditions: nil,
			},
		},
		DefaultBackendUpstreamName: "",
		XForwardedPrefix:           "",
		Logs: log.Config{
			Access:  false,
			Rewrite: false,
		},
		InfluxDB: influxdb.Config{
			InfluxDBEnabled:     false,
			InfluxDBMeasurement: "",
			InfluxDBPort:        "",
			InfluxDBHost:        "",
			InfluxDBServerName:  "",
		},
		BackendProtocol: "",
		FastCGI: fastcgi.Config{
			Index:  "",
			Params: nil,
		},
		CustomHTTPErrors: nil,
		ModSecurity: modsecurity.Config{
			Enable:        false,
			EnableSet:     false,
			OWASPRules:    false,
			TransactionID: "",
			Snippet:       "",
		},
		Satisfy: "",
		Mirror: mirror.Config{
			Source:      "",
			RequestBody: "",
			Target:      "",
		},
		Opentracing: opentracing.Config{
			Enabled: false,
			Set:     false,
		},
	}
}
