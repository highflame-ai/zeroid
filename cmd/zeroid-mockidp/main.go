// Command zeroid-mockidp serves a fake Entra tenant, Okta org and Kubernetes
// issuer for local end-to-end runs of trusted issuers. See README.md.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/highflame-ai/zeroid/internal/mockidp"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	base := flag.String("base-url", "http://localhost:8080", "URL the issuers are published under; must be how ZeroID reaches this server")
	flag.Parse()

	idp, err := mockidp.New(*base)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mock IdP on %s", *addr)
	log.Printf("  entra issuer  %s", idp.EntraIssuer(mockidp.DefaultEntraTenant))
	log.Printf("  okta issuer   %s", idp.OktaIssuer())
	log.Printf("  k8s issuer    %s", idp.K8sIssuer())
	srv := &http.Server{Addr: *addr, Handler: idp.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
