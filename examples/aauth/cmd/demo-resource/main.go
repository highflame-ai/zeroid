// Command demo-resource serves the demo resource (see demo.NewResource): an
// AAuth resource at /whoami, guarded by aauth-go, and an OAuth-only MCP-style
// endpoint at /mcp that accepts ZeroID's bridged DPoP-bound tokens. It listens
// on plain http behind the compose demo's TLS proxy.
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/highflame-ai/zeroid/examples/aauth/demo"
)

func main() {
	issuer := demo.Env("ZEROID_ISSUER", "https://auth.zeroid.test")
	resource := demo.Env("RESOURCE", "https://resource.zeroid.test")
	client, err := demo.ClientTrusting(demo.Env("CA_FILE", ""), time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	h, err := demo.NewResource(demo.ResourceConfig{
		Resource:       resource,
		AgentProviders: []string{issuer},
		ZeroIDIssuer:   issuer,
		HTTPClient:     client,
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := demo.Env("LISTEN", ":8080")
	log.Printf("demo resource %s on %s (trusting agent provider %s)", resource, addr, issuer)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
