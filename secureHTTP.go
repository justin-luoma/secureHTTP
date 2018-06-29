package secureHTTP // import "github.com/justin-luoma/secureHTTP"
import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
)

var TlsConfig = &tls.Config{
	MinVersion:               tls.VersionTLS12,
	PreferServerCipherSuites: true,
	CurvePreferences: []tls.CurveID{
		tls.CurveP521,
		tls.CurveP384,
		tls.CurveP256,
		tls.X25519,
	},
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
}

const XFrameOptions = "SAMEORIGIN"
const XContentTypeOptions = "nosniff"
const StrictTransportSecurity = "max-age=3600"
const ContentSecurityPolicy = "default-src https"

type secureServer struct {
	Certificate                   string
	PrivateKey                    string
	TlsConfig                     *tls.Config
	ReadTimeout                   time.Duration
	WriteTimeout                  time.Duration
	IdleTimeout                   time.Duration
	Address                       string
	Mux                           http.Handler
	EnableLogging                 bool
	LoggingOut                    io.Writer
	EnableXFrameOptions           bool
	XFrameOptions                 string
	EnableXContentType            bool
	XContentTypeOptions           string
	EnableStrictTransportSecurity bool
	StrictTransportSecurity       string
	EnableContentSecurityPolicy   bool
	ContentSecurityPolicy         string
	httpSrv                       *http.Server
}

func New(address string, certificate string, privateKey string, mux http.Handler) *secureServer {
	s := secureServer{
		Certificate:                   certificate,
		PrivateKey:                    privateKey,
		TlsConfig:                     TlsConfig,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  5 * time.Second,
		IdleTimeout:                   120 * time.Second,
		Address:                       address,
		Mux:                           mux,
		EnableLogging:                 true,
		LoggingOut:                    os.Stdout,
		EnableXFrameOptions:           true,
		XFrameOptions:                 XFrameOptions,
		EnableXContentType:            true,
		XContentTypeOptions:           XContentTypeOptions,
		EnableStrictTransportSecurity: true,
		StrictTransportSecurity:       StrictTransportSecurity,
		EnableContentSecurityPolicy:   true,
		ContentSecurityPolicy:         ContentSecurityPolicy,
	}

	return &s
}

func NewWithOptions(certificate string, privateKey string, tlsConfig *tls.Config, readTimeout time.Duration, writeTimeout time.Duration, idleTimeout time.Duration, address string, mux http.Handler, enableLogging bool,
	loggingOut io.Writer, enableXFrameOptions bool, XFrameOptions string, enableXContentType bool, xContentTypeOptions string, enableStrictTransportSecurity bool, strictTransportSecurity string,
	enableContentSecurityPolicy bool, contentSecurityPolicy string) *secureServer {

	s := secureServer{
		Certificate:                   certificate,
		PrivateKey:                    privateKey,
		TlsConfig:                     tlsConfig,
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		IdleTimeout:                   idleTimeout,
		Address:                       address,
		Mux:                           mux,
		EnableLogging:                 enableLogging,
		LoggingOut:                    loggingOut,
		EnableXFrameOptions:           enableXFrameOptions,
		XFrameOptions:                 XFrameOptions,
		EnableXContentType:            enableXContentType,
		XContentTypeOptions:           xContentTypeOptions,
		EnableStrictTransportSecurity: enableStrictTransportSecurity,
		StrictTransportSecurity:       strictTransportSecurity,
		EnableContentSecurityPolicy:   enableContentSecurityPolicy,
		ContentSecurityPolicy:         contentSecurityPolicy,
	}

	return &s
}

func (srv *secureServer) Serve() error {
	httpsSrv := &http.Server{
		TLSConfig:    srv.TlsConfig,
		ReadTimeout:  srv.ReadTimeout,
		WriteTimeout: srv.WriteTimeout,
		IdleTimeout:  srv.IdleTimeout,
		Addr:         srv.Address,
	}

	headers := srv.EnableXFrameOptions || srv.EnableXContentType || srv.EnableStrictTransportSecurity || srv.EnableContentSecurityPolicy
	switch {
	case srv.EnableLogging && headers:
		loggingRtr := handlers.CombinedLoggingHandler(srv.LoggingOut, srv.Mux)
		httpsSrv.Handler = srv.headerHandler(loggingRtr)
	case srv.EnableLogging && !headers:
		httpsSrv.Handler = handlers.CombinedLoggingHandler(srv.LoggingOut, srv.Mux)
	case !srv.EnableLogging && headers:
		httpsSrv.Handler = srv.headerHandler(srv.Mux)
	}

	srv.httpSrv = httpsSrv
	return srv.httpSrv.ListenAndServeTLS(srv.Certificate, srv.PrivateKey)
}

func (srv *secureServer) Shutdown(ctx context.Context) error {
	return srv.httpSrv.Shutdown(ctx)
}

func (srv *secureServer) headerHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.setHeaders(w)
		h.ServeHTTP(w, r)
	})
}

func (srv *secureServer) setHeaders(w http.ResponseWriter) {
	if srv.EnableXFrameOptions {
		w.Header().Set("X-Frame-Options", srv.XFrameOptions)
	}
	if srv.EnableXContentType {
		w.Header().Set("X-Content-Type-Options", srv.XContentTypeOptions)
	}
	if srv.EnableStrictTransportSecurity {
		w.Header().Set("Strict-Transport-Security", srv.StrictTransportSecurity)
	}
	if srv.EnableContentSecurityPolicy {
		w.Header().Set("Content-Security-Policy", srv.ContentSecurityPolicy)
	}
}
