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

const (
	// XFrameOptions default setting for X-Frame-Options header
	XFrameOptions           = "SAMEORIGIN"
	// XContentTypeOptions default setting for X-Content-Type header
	XContentTypeOptions     = "nosniff"
	// StrictTransportSecurity default setting for Strict-Transport-Security header
	StrictTransportSecurity = "max-age=31536000"
	// ContentSecurityPolicy default setting for Content-Security-Policy header
	ContentSecurityPolicy   = "default-src https"
	readTimeout             = 5 * time.Second
	writeTimeout            = 5 * time.Second
	idleTimeout             = 120 * time.Second
)

// Options struct contains all the setting for secureHTTP
type Options struct {
	// TLSConfig contains the tls server settings see TLSConfig struct and https://godoc.org/crypto/tls#Config
	TLSConfig                     *tls.Config
	// ReadTimeout for http server default 5 seconds. See https://godoc.org/net/http#Server
	ReadTimeout                   time.Duration
	// WriteTimeout for http server default 5 seconds. See https://godoc.org/net/http#Server
	WriteTimeout                  time.Duration
	// IdleTimeout for http server default 120 seconds. See https://godoc.org/net/http#Server
	IdleTimeout                   time.Duration
	// EnableLogging enable access logs via gorilla/handlers default true
	EnableLogging                 bool
	// LoggingOut where to send logging data default StdOut
	LoggingOut                    io.Writer
	// EnableXFrameOptions enables X-Frame-options header injection to all responses, default true
	EnableXFrameOptions           bool
	// XFrameOptions is the content of the X-Frame-options header, default SAMEORIGIN
	XFrameOptions                 string
	// EnableXContentType enables X-Content-Type header injection into all responses, default true
	EnableXContentType            bool
	// XContentTypeOptions sets the content of X-Content-Type header, default nosniff
	XContentTypeOptions           string
	// EnableStrictTransportSecurity enables Strict-Transport-Security header injection into all responses, default true
	EnableStrictTransportSecurity bool
	// StrictTransportSecurity sets the content of Strict-Transport-Security header, default max-age=31536000
	StrictTransportSecurity       string
	// EnableContentSecurityPolicy enables Content-Security-Policy header injection into all responses, default true
	EnableContentSecurityPolicy   bool
	// ContentSecurityPolicy sets the content of Content-Security-Policy header, default default-src https
	ContentSecurityPolicy         string
}

//TLSConfig contains secure curve preferences and cipher suites for the default tls options
var TLSConfig = &tls.Config{
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

// SecureServer implements a secure HTTP middleware will strong default options
type SecureServer struct {
	options     *Options
	certificate string
	privateKey  string
	httpSrv     *http.Server
}

var defaultOptions = Options{
	TLSConfig:                     TLSConfig,
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

// New returns a secureServer with the default options
func New(certificate string, privateKey string) *SecureServer {
	s := SecureServer{
		certificate: certificate,
		privateKey:  privateKey,
		options:     &defaultOptions,
	}

	return &s
}

// NewWithOptions returns a secureServer with the provided custom options
func NewWithOptions(certificate string, privateKey string, options *Options) *SecureServer {

	s := SecureServer{
		certificate: certificate,
		privateKey:  privateKey,
		options:     options,
	}

	return &s
}

// Serve starts http.ListenAndServeTLS with the configured options and returns its error
func (srv *SecureServer) Serve(address string, mux http.Handler) error {
	httpsSrv := &http.Server{
		TLSConfig:    srv.options.TLSConfig,
		ReadTimeout:  srv.options.ReadTimeout,
		WriteTimeout: srv.options.WriteTimeout,
		IdleTimeout:  srv.options.IdleTimeout,
		Addr:         address,
		Handler:      mux,
	}

	headers := srv.options.EnableXFrameOptions || srv.options.EnableXContentType || srv.options.EnableStrictTransportSecurity || srv.options.EnableContentSecurityPolicy
	switch {
	case srv.options.EnableLogging && headers:
		loggingRtr := handlers.CombinedLoggingHandler(srv.options.LoggingOut, mux)
		httpsSrv.Handler = srv.headerHandler(loggingRtr)
	case srv.options.EnableLogging && !headers:
		httpsSrv.Handler = handlers.CombinedLoggingHandler(srv.options.LoggingOut, mux)
	case !srv.options.EnableLogging && headers:
		httpsSrv.Handler = srv.headerHandler(mux)
	}

	srv.httpSrv = httpsSrv
	return srv.httpSrv.ListenAndServeTLS(srv.certificate, srv.privateKey)
}

// Shutdown stops http.ListenAndServeTLS cleanly
func (srv *SecureServer) Shutdown(ctx context.Context) error {
	return srv.httpSrv.Shutdown(ctx)
}

func (srv *SecureServer) headerHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.setHeaders(w)
		h.ServeHTTP(w, r)
	})
}

func (srv *SecureServer) setHeaders(w http.ResponseWriter) {
	if srv.options.EnableXFrameOptions {
		w.Header().Set("X-Frame-options", srv.options.XFrameOptions)
	}
	if srv.options.EnableXContentType {
		w.Header().Set("X-Content-Type-options", srv.options.XContentTypeOptions)
	}
	if srv.options.EnableStrictTransportSecurity {
		w.Header().Set("Strict-Transport-Security", srv.options.StrictTransportSecurity)
	}
	if srv.options.EnableContentSecurityPolicy {
		w.Header().Set("Content-Security-Policy", srv.options.ContentSecurityPolicy)
	}
}
