package zeroid

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AuditFeedEntry is one identity_audit_logs row with its place in the feed.
type AuditFeedEntry = postgres.AuditFeedEntry

// AuditFeedPage is one read of the identity audit feed, and the cursor to
// pass to the next read.
type AuditFeedPage struct {
	Entries  []AuditFeedEntry `json:"rows"`
	NextTxID string           `json:"next_txid"`
	NextSeq  int64            `json:"next_seq"`
}

// MaxAuditFeedLimit caps one read of the identity audit feed.
const MaxAuditFeedLimit = 1000

// ErrInvalidAuditCursor reports an after-txid that is not a transaction id.
var ErrInvalidAuditCursor = errors.New("invalid audit feed cursor")

// IdentityAuditFeed returns up to limit identity_audit_logs rows after the
// (afterTxID, afterSeq) cursor, oldest first, across every tenant. Start
// from ("0", 0). Only rows from finished transactions are returned, so a
// consumer that pages with NextTxID and NextSeq sees every row exactly once,
// including one whose transaction commits after later rows. An embedding
// service exposes this to its consumers; ZeroID serves no route
// for it.
func (s *Server) IdentityAuditFeed(ctx context.Context, afterTxID string, afterSeq int64, limit int) (*AuditFeedPage, error) {
	if _, err := strconv.ParseUint(afterTxID, 10, 64); err != nil || afterSeq < 0 {
		return nil, fmt.Errorf("%w: %q, %d", ErrInvalidAuditCursor, afterTxID, afterSeq)
	}

	limit = min(max(limit, 1), MaxAuditFeedLimit)

	entries, err := postgres.NewAuditLogRepository(s.db).Feed(ctx, afterTxID, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("read identity audit feed: %w", err)
	}

	page := &AuditFeedPage{Entries: entries, NextTxID: afterTxID, NextSeq: afterSeq}
	if n := len(entries); n > 0 {
		page.NextTxID, page.NextSeq = entries[n-1].TxID, entries[n-1].Seq
	}

	return page, nil
}
