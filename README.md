# secureHTTP
[![GoDoc](https://godoc.org/github.com/justin-luoma/secureHTTP?status.svg)](https://godoc.org/github.com/justin-luoma/secureHTTP) [![Go Report Card](https://goreportcard.com/badge/github.com/justin-luoma/secureHTTP)](https://goreportcard.com/report/github.com/justin-luoma/secureHTTP) [![Build Status](https://travis-ci.org/justin-luoma/secureHTTP.svg?branch=master)](https://travis-ci.org/justin-luoma/secureHTTP)

secureHTTP is a HTTP middleware to implement a secure web server in go that is safe to expose to the internet.

## Install

    go get github.com/justin-luoma/secureHTTP

## Usage

cert.pem and key.pem are needed to run the example code, to generate them:

    go run $GOROOT/src/crypto/tls/generate_cert.go --host "localhost" --ecdsa-curve "P384"


###### Default Settings:
***

~~~go
// main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/justin-luoma/secureHTTP"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Write([]byte("Hello, World!\n"))
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	srv := secureHTTP.New("cert.pem", "key.pem")
	go func() {
		log.Fatal(srv.Serve(":443", mux))
	}()

	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}
~~~

###### Custom Settings:
***

~~~go
// main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/justin-luoma/secureHTTP"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Write([]byte("Hello, World!\n"))
	})

	options := secureHTTP.Options{
		TlsConfig:                     secureHTTP.TlsConfig,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  5 * time.Second,
		IdleTimeout:                   120 * time.Second,
		EnableLogging:                 true,
		LoggingOut:                    os.Stdout,
		EnableStrictTransportSecurity: true,
		StrictTransportSecurity:       "max-age=3600",
		EnableXContentType:            true,
		XContentTypeOptions:           "nosniff",
		EnableContentSecurityPolicy:   true,
		ContentSecurityPolicy:         "default-src https",
		EnableXFrameOptions:           true,
		XFrameOptions:                 "SAMEORIGIN",
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	srv := secureHTTP.NewWithOptions("cert.pem", "key.pem", &options)

	go func() {
		log.Fatal(srv.Serve(":443", mux))
	}()

	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}
~~~

###### gorilla/mux:
***

~~~go
// main.go
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/justin-luoma/secureHTTP"
)

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	io.WriteString(w, `{"alive": true}`)
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/health", HealthCheckHandler)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	srv := secureHTTP.New("cert.pem", "key.pem")
	go func() {
		log.Fatal(srv.Serve(":443", r))
	}()

	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}
~~~

###### go-chi/chi:
***

~~~go
// main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-chi/chi"
	"github.com/justin-luoma/secureHTTP"
)

func main() {

	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	srv := secureHTTP.New("cert.pem", "key.pem")
	go func() {
		log.Fatal(srv.Serve(":443", r))
	}()

	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
}
~~~

# TODO

 - Write tests
 - Improve documentation
 - Implement HTTP redirect server
