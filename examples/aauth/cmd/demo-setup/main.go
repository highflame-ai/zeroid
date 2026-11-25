// Command demo-setup does what an admin does once, through ZeroID's own admin
// API: a credential policy that opts into AAuth, an agent identity, the
// cluster's workload issuer row and the service account's binding. It is
// idempotent enough for a demo: run against a fresh database.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/highflame-ai/zeroid/examples/aauth/demo"
)

func main() {
	admin := demo.Env("ZEROID_ADMIN_URL", "http://zeroid:8899")
	issuer := demo.Env("ZEROID_ISSUER", "https://auth.zeroid.test")
	clusterIssuer := demo.Env("CLUSTER_ISSUER", "http://mockidp:8080/k8s")
	subject := demo.Env("SA_SUBJECT", "system:serviceaccount:agents:planner")
	headers := map[string]string{
		"X-Account-ID": demo.Env("ACCOUNT_ID", "acme"),
		"X-Project-ID": demo.Env("PROJECT_ID", "prod"),
	}

	waitFor(admin + "/health")
	policy := call(admin, http.MethodPost, "/credential-policies", headers, map[string]any{
		"name":                "aauth-demo",
		"allowed_grant_types": []string{"aauth_agent", "aauth_bridge"},
		"allowed_scopes":      []string{"tools:read"},
		"max_ttl_seconds":     3600,
	})
	identity := call(admin, http.MethodPost, "/identities", headers, map[string]any{
		"external_id": "planner", "identity_type": "agent", "trust_level": "unverified",
		"owner_user_id": "alice", "credential_policy_id": policy["id"],
	})
	row := call(admin, http.MethodPost, "/external-issuers", headers, map[string]any{
		"kind": "workload", "display_name": "Demo cluster", "issuer": clusterIssuer, "audiences": []string{issuer},
	})
	call(admin, http.MethodPost, "/external-issuers/"+fmt.Sprint(row["id"])+"/bindings", headers, map[string]any{
		"subject_key": subject, "identity_id": identity["id"],
	})
	fmt.Printf("seeded: identity %v (%v), bound to %s under %s\n", identity["id"], identity["wimse_uri"], subject, clusterIssuer)
}

func waitFor(url string) {
	for i := 0; i < 60; i++ {
		if resp, err := http.Get(url); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	log.Fatalf("%s never became healthy", url)
}

func call(base, method, path string, headers map[string]string, body any) map[string]any {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(method, base+path, bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		log.Printf("%s %s: %d %s", method, path, resp.StatusCode, raw)
		os.Exit(1)
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}
