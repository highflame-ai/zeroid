// Command demo-agent is a workload that holds no secrets: it gets its
// platform token, keeps one Ed25519 key for its pod, enrolls at ZeroID's
// AAuth Agent Provider with aauth-go's client, calls an AAuth resource with
// aauth-go's signing transport, then bridges to an OAuth-only MCP resource.
// It narrates each step.
//
// PLATFORM chooses where the platform token comes from: mockidp (local, the
// default), k8s (a projected token file) or aws (STS web identity token). Only
// mockidp is exercised by the local demo.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"

	"github.com/highflame-ai/zeroid/examples/aauth/demo"
)

func main() {
	issuer := demo.Env("ZEROID_ISSUER", "https://auth.zeroid.test")
	resource := demo.Env("RESOURCE", "https://resource.zeroid.test")
	ctx := context.Background()

	client, err := demo.ClientTrusting(demo.Env("CA_FILE", ""), time.Minute)
	must(err)

	var platform demo.PlatformToken
	switch p := demo.Env("PLATFORM", "mockidp"); p {
	case "mockidp":
		platform = demo.MockIdPToken(http.DefaultClient, demo.Env("MOCKIDP_URL", "http://mockidp:8080"),
			demo.Env("SA_SUBJECT", "system:serviceaccount:agents:planner"))
	case "k8s":
		platform = demo.FileToken(demo.Env("TOKEN_FILE", "/var/run/secrets/zeroid/token"))
	case "aws":
		platform = demo.AWSToken(os.Getenv("AWS_SIGNING_ALGORITHM"))
	default:
		log.Fatalf("PLATFORM %q: want mockidp, k8s or aws", p)
	}

	step(1, "Platform identity token (no secret anywhere)")
	token, err := platform(ctx, issuer)
	must(err)
	claims := payload(token)
	fmt.Printf("    iss %v\n    sub %v\n    aud %v\n", claims["iss"], claims["sub"], claims["aud"])

	step(2, "Agent key, one per pod")
	keyFile := demo.Env("KEY_FILE", "/pod/agent.key")
	key, err := demo.LoadOrCreateKey(keyFile)
	must(err)
	fmt.Printf("    Ed25519 key at %s\n", keyFile)

	step(3, "Enroll at ZeroID's Agent Provider (aauth-go client, hwk-signed)")
	ap := &agentprovider.Client{BaseURL: issuer, HTTPClient: client}
	agent, err := ap.Enroll(ctx, key, map[string]string{"attestation": token})
	must(err)
	agentToken, err := agent.MintToken()
	must(err)
	ac := payload(agentToken)
	fmt.Printf("    agent %v\n    iss   %v\n    cnf   bound to this pod's key\n    exp   in %ds\n",
		ac["sub"], ac["iss"], int64(ac["exp"].(float64))-time.Now().Unix())

	step(4, "Call an AAuth resource (aauth-go signs; the resource verifies via ZeroID's JWKS)")
	transport := aauth.NewTransport(agent, nil)
	transport.Base = client.Transport
	resp, err := (&http.Client{Transport: transport, Timeout: 15 * time.Second}).Get(resource + "/whoami")
	must(err)
	var who map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&who)
	_ = resp.Body.Close()
	fmt.Printf("    %d %v\n", resp.StatusCode, who)

	step(5, "Bridge to OAuth for an MCP server (DPoP-bound, one resource)")
	access, err := demo.Bridge(ctx, client, issuer, agentToken, key, resource, "tools:read")
	must(err)
	bc := payload(access)
	fmt.Printf("    sub %v\n    aauth_agent %v\n    aud %v\n", bc["sub"], bc["aauth_agent"], bc["aud"])

	step(6, "Call the MCP tool")
	out, err := demo.CallMCP(ctx, client, resource+"/mcp", access, key, "search")
	must(err)
	fmt.Printf("    %v\n", out["result"])
	fmt.Println("\nDone: no secret was stored, shipped or exchanged.")
}

func step(n int, title string) { fmt.Printf("\n[%d] %s\n", n, title) }

func payload(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	out := map[string]any{}
	if len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(b, &out)
		}
	}
	return out
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
