package service

import (
	"context"
	"errors"
	"testing"
)

// ADR 0053 D3: CreateKey refuses the management mark unless the caller's
// context was marked by the embedding service's trusted path, before any
// lookup or insert.
func TestCreateKeyRefusesUntrustedManagement(t *testing.T) {
	_, err := (&APIKeyService{}).CreateKey(context.Background(), CreateAPIKeyRequest{Management: true})
	if !errors.Is(err, ErrManagementKeyWriteNotTrusted) {
		t.Fatalf("want ErrManagementKeyWriteNotTrusted, got %v", err)
	}

	_, err = (&APIKeyService{}).CreateKey(WithManagementKeyWrite(context.Background()), CreateAPIKeyRequest{Management: true})
	if errors.Is(err, ErrManagementKeyWriteNotTrusted) {
		t.Fatal("a marked context must pass the management check")
	}
}
