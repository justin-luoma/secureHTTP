/*
Package secureHTTP is an HTTP middleware to implement a secure web server in go that is safe to expose to the internet.

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
*/
package secureHTTP
