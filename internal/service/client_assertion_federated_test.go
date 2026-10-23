package service

import "testing"

func TestFederatedClientID(t *testing.T) {
	cases := map[string]struct{ iss, sub, want string }{
		"AWS role ARN is globally unique":               {"https://abc.tokens.sts.global.api.aws", "arn:aws:iam::111122223333:role/agent", "arn:aws:iam::111122223333:role/agent"},
		"SPIFFE ID names its trust domain":              {"https://spire.example", "spiffe://example.org/agent", "spiffe://example.org/agent"},
		"Kubernetes subject is qualified by its issuer": {"https://cluster-a.example", "system:serviceaccount:agents:foo", "https://cluster-a.example#system:serviceaccount:agents:foo"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := federatedClientID(tc.iss, tc.sub); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if federatedClientID("https://cluster-a.example", "system:serviceaccount:agents:foo") ==
		federatedClientID("https://cluster-b.example", "system:serviceaccount:agents:foo") {
		t.Fatal("two clusters' service accounts must not share a client_id")
	}
}
