package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ihatemyfcklife/badsharing/signaling"
)

func main() {
	addr:=flag.String("listen","127.0.0.1:8088","rendezvous HTTP/TLS listen address")
	cert:=flag.String("tls-cert","","TLS public certificate file (required on public interfaces)")
	keyFile:=flag.String("tls-key","","TLS private key file (required on public interfaces)")
	flag.Parse()
	token:=os.Getenv("BADSHARING_SIGNAL_TOKEN")
	broker,err:=signaling.NewServer(token)
	if err!=nil {log.Fatal(err)}
	host,_,err:=net.SplitHostPort(*addr)
	if err!=nil {log.Fatal(err)}
	ip:=net.ParseIP(host)
	loopback:=host=="localhost"||(ip!=nil&&ip.IsLoopback())
	if !loopback&&(*cert==""||*keyFile=="") {
		log.Fatal("public signaling interface requires TLS certificates")
	}
	if (*cert=="")!=(*keyFile=="") {
		log.Fatal("set both tls-cert and tls-key")
	}
	srv:=&http.Server{
		Addr:*addr,Handler:broker,
		ReadHeaderTimeout:5*time.Second,
		ReadTimeout:10*time.Second,
		WriteTimeout:10*time.Second,
		IdleTimeout:30*time.Second,
		MaxHeaderBytes:8192,
	}
	fmt.Printf("badsharing rendezvous listening on %s\n",*addr)
	if *cert!="" {err=srv.ListenAndServeTLS(*cert,*keyFile)} else {err=srv.ListenAndServe()}
	if err!=nil&&err!=http.ErrServerClosed {log.Fatal(err)}
}
