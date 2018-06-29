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

const (
	XFrameOptions           = "SAMEORIGIN"
	XContentTypeOptions     = "nosniff"
	StrictTransportSecurity = "max-age=3600"
	ContentSecurityPolicy   = "default-src https"
	readTimeout             = 5 * time.Second
	writeTimeout            = 5 * time.Second
	idleTimeout             = 5 * time.Second
)

type secureServer struct {
	Options     *Options
	Certificate string
	PrivateKey  string
	Mux         http.Handler
	httpSrv     *http.Server
}

type Options struct {
	TlsConfig                     *tls.Config
	ReadTimeout                   time.Duration
	WriteTimeout                  time.Duration
	IdleTimeout                   time.Duration
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
}

var defaultOptions = Options{
	TlsConfig:                     TlsConfig,
	ReadTimeout:                   readTimeout,
	WriteTimeout:                  writeTimeout,
	IdleTimeout:                   idleTimeout,
	EnableLogging:                 true,
	LoggingOut:                    os.Stdout,
	EnableXFrameOptions:           true,
	XFrameOptions:                 XFrameOptions,
	EnableContentSecurityPolicy:   true,
	ContentSecurityPolicy:         ContentSecurityPolicy,
	EnableXContentType:            true,
	XContentTypeOptions:           XContentTypeOptions,
	EnableStrictTransportSecurity: true,
	StrictTransportSecurity:       StrictTransportSecurity,
}

func New(certificate string, privateKey string) *secureServer {
	s := secureServer{
		Certificate: certificate,
		PrivateKey:  privateKey,
		Options:     &defaultOptions,
	}

	return &s
}

func NewWithOptions(certificate string, privateKey string, options *Options) *secureServer {

	s := secureServer{
		Certificate: certificate,
		PrivateKey:  privateKey,
		Options:     options,
	}

	return &s
}

func (srv *secureServer) Serve(address string, mux http.Handler) error {
	httpsSrv := &http.Server{
		TLSConfig:    srv.Options.TlsConfig,
		ReadTimeout:  srv.Options.ReadTimeout,
		WriteTimeout: srv.Options.WriteTimeout,
		IdleTimeout:  srv.Options.IdleTimeout,
		Addr:         address,
		Handler:      mux,
	}

	headers := srv.Options.EnableXFrameOptions || srv.Options.EnableXContentType || srv.Options.EnableStrictTransportSecurity || srv.Options.EnableContentSecurityPolicy
	switch {
	case srv.Options.EnableLogging && headers:
		loggingRtr := handlers.CombinedLoggingHandler(srv.Options.LoggingOut, mux)
		httpsSrv.Handler = srv.headerHandler(loggingRtr)
	case srv.Options.EnableLogging && !headers:
		httpsSrv.Handler = handlers.CombinedLoggingHandler(srv.Options.LoggingOut, mux)
	case !srv.Options.EnableLogging && headers:
		httpsSrv.Handler = srv.headerHandler(mux)
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
	if srv.Options.EnableXFrameOptions {
		w.Header().Set("X-Frame-Options", srv.Options.XFrameOptions)
	}
	if srv.Options.EnableXContentType {
		w.Header().Set("X-Content-Type-Options", srv.Options.XContentTypeOptions)
	}
	if srv.Options.EnableStrictTransportSecurity {
		w.Header().Set("Strict-Transport-Security", srv.Options.StrictTransportSecurity)
	}
	if srv.Options.EnableContentSecurityPolicy {
		w.Header().Set("Content-Security-Policy", srv.Options.ContentSecurityPolicy)
	}
}
