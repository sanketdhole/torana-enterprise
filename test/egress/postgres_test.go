package egress_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/egress/postgres"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
)

type fakeRowReader struct {
	cols []string
	data [][]any
	idx  int
	err  error
}

func (r *fakeRowReader) Columns() []string { return r.cols }
func (r *fakeRowReader) Next() bool {
	if r.idx < len(r.data) {
		r.idx++
		return true
	}
	return false
}
func (r *fakeRowReader) Values() ([]any, error) {
	if r.idx <= 0 || r.idx > len(r.data) {
		return nil, errors.New("out of bounds")
	}
	return r.data[r.idx-1], nil
}
func (r *fakeRowReader) Err() error { return r.err }
func (r *fakeRowReader) Close()      {}

type fakeDBPool struct {
	mu           sync.Mutex
	lastSQL      string
	lastReadOnly bool
	lastArgs     []any
	queryFn      func(ctx context.Context, sql string, readOnly bool, args ...any) (postgres.RowReader, error)
}

func (p *fakeDBPool) Query(ctx context.Context, sql string, readOnly bool, args ...any) (postgres.RowReader, error) {
	p.mu.Lock()
	p.lastSQL = sql
	p.lastReadOnly = readOnly
	p.lastArgs = args
	p.mu.Unlock()

	if p.queryFn != nil {
		return p.queryFn(ctx, sql, readOnly, args...)
	}
	return &fakeRowReader{
		cols: []string{"id", "name"},
		data: [][]any{{int64(1), "alice"}, {int64(2), "bob"}},
	}, nil
}

func (p *fakeDBPool) Close() {}

func setupPostgresAuthzEngine(t *testing.T) *authz.PolicyEngine {
	compiler, err := authz.NewCompiler(authz.CompilerConfig{CostLimit: 1000})
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	rules := []authz.Rule{
		{
			ID:         "allow-get-user",
			Priority:   50,
			Effect:     authz.EffectAllow,
			Expression: `resource.type == 'db_query' && resource.id == 'get_user_by_id'`,
		},
		{
			ID:         "deny-delete-all",
			Priority:   100,
			Effect:     authz.EffectDeny,
			Expression: `resource.type == 'db_query' && resource.id == 'delete_all_users'`,
		},
	}

	compiled, err := compiler.CompileRules(rules)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}
	return authz.NewPolicyEngine(compiled, nil)
}

func TestPostgres_NamedQueriesOnly(t *testing.T) {
	client := postgres.NewClient(nil, nil)
	pool := &fakeDBPool{}
	client.RegisterTarget("target-db", pool, 10, 10)

	client.RegisterNamedQuery(postgres.NamedQuery{
		Name: "get_user_by_id",
		SQL:  "SELECT id, name FROM users WHERE id = $1",
		Params: []postgres.ParamSpec{
			{Name: "id", Type: postgres.ParamTypeInt, Required: true},
		},
	})

	t.Run("Rejects Unregistered Query", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "unknown_query",
			Params:    map[string]any{},
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if !errors.Is(err, postgres.ErrUnknownNamedQuery) {
			t.Fatalf("expected ErrUnknownNamedQuery, got %v", err)
		}
	})

	t.Run("Executes Registered Named Query", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "get_user_by_id",
			Params:    map[string]any{"id": 42},
		}
		res, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.RowCount != 2 {
			t.Fatalf("expected 2 rows, got %d", res.RowCount)
		}
		if pool.lastSQL != "SELECT id, name FROM users WHERE id = $1" {
			t.Fatalf("unexpected sql executed: %s", pool.lastSQL)
		}
		if len(pool.lastArgs) != 1 || pool.lastArgs[0] != int64(42) {
			t.Fatalf("unexpected args passed: %v", pool.lastArgs)
		}
	})
}

func TestPostgres_AuthzEnforcement(t *testing.T) {
	authzEngine := setupPostgresAuthzEngine(t)
	client := postgres.NewClient(authzEngine, nil)
	pool := &fakeDBPool{}
	client.RegisterTarget("target-db", pool, 10, 10)

	client.RegisterNamedQuery(postgres.NamedQuery{
		Name: "get_user_by_id",
		SQL:  "SELECT id FROM users WHERE id = $1",
	})
	client.RegisterNamedQuery(postgres.NamedQuery{
		Name: "delete_all_users",
		SQL:  "DELETE FROM users",
	})

	env := &pipeline.Envelope{
		Path:   "/api/db",
		Method: "POST",
		Identity: &authn.Identity{
			Subject: "analyst-dave",
		},
	}

	t.Run("Allowed named query succeeds", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "get_user_by_id",
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, env)
		if err != nil {
			t.Fatalf("expected allowed query to succeed, got %v", err)
		}
	})

	t.Run("Denied named query returns ErrUnauthorizedDBQuery", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "delete_all_users",
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, env)
		if !errors.Is(err, postgres.ErrUnauthorizedDBQuery) {
			t.Fatalf("expected ErrUnauthorizedDBQuery, got %v", err)
		}
	})
}

func TestPostgres_TypedParamsValidation(t *testing.T) {
	client := postgres.NewClient(nil, nil)
	pool := &fakeDBPool{}
	client.RegisterTarget("target-db", pool, 10, 10)

	client.RegisterNamedQuery(postgres.NamedQuery{
		Name: "complex_filter",
		SQL:  "SELECT * FROM items WHERE score >= $1 AND active = $2 AND label = $3",
		Params: []postgres.ParamSpec{
			{Name: "score", Type: postgres.ParamTypeFloat, Required: true},
			{Name: "active", Type: postgres.ParamTypeBool, Required: true},
			{Name: "label", Type: postgres.ParamTypeString, Required: false},
		},
	})

	t.Run("Missing required parameter fails", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "complex_filter",
			Params: map[string]any{
				"active": true,
			},
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if !errors.Is(err, postgres.ErrMissingRequiredParam) {
			t.Fatalf("expected ErrMissingRequiredParam, got %v", err)
		}
	})

	t.Run("Invalid type coercion fails", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "complex_filter",
			Params: map[string]any{
				"score":  "not-a-float",
				"active": true,
			},
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if !errors.Is(err, postgres.ErrInvalidParamType) {
			t.Fatalf("expected ErrInvalidParamType, got %v", err)
		}
	})

	t.Run("Valid typed parameters succeed and coerce", func(t *testing.T) {
		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "complex_filter",
			Params: map[string]any{
				"score":  float64(88.5),
				"active": true,
				"label":  "prod",
			},
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pool.lastArgs) != 3 {
			t.Fatalf("expected 3 arguments, got %d", len(pool.lastArgs))
		}
		if pool.lastArgs[0] != float64(88.5) || pool.lastArgs[1] != true || pool.lastArgs[2] != "prod" {
			t.Fatalf("unexpected coerced arguments: %v", pool.lastArgs)
		}
	})
}

func TestPostgres_RowAndByteLimits(t *testing.T) {
	client := postgres.NewClient(nil, nil)

	// Create pool returning 100 rows
	manyRows := make([][]any, 100)
	for i := 0; i < 100; i++ {
		manyRows[i] = []any{int64(i), "large text string payload"}
	}

	pool := &fakeDBPool{
		queryFn: func(ctx context.Context, sql string, readOnly bool, args ...any) (postgres.RowReader, error) {
			return &fakeRowReader{
				cols: []string{"id", "val"},
				data: manyRows,
			}, nil
		},
	}
	client.RegisterTarget("target-db", pool, 10, 10)

	t.Run("MaxRows truncation", func(t *testing.T) {
		client.RegisterNamedQuery(postgres.NamedQuery{
			Name:    "query_limited_rows",
			SQL:     "SELECT * FROM items",
			MaxRows: 15,
		})

		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "query_limited_rows",
		}
		res, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.RowCount != 15 {
			t.Fatalf("expected 15 rows, got %d", res.RowCount)
		}
		if !res.Truncated {
			t.Fatalf("expected Truncated flag to be true")
		}
	})

	t.Run("MaxBytes exceeded error", func(t *testing.T) {
		client.RegisterNamedQuery(postgres.NamedQuery{
			Name:     "query_limited_bytes",
			SQL:      "SELECT * FROM items",
			MaxBytes: 50, // Extremely small limit, will be tripped quickly
		})

		req := &postgres.QueryRequest{
			TargetID:  "target-db",
			QueryName: "query_limited_bytes",
		}
		_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
		if !errors.Is(err, postgres.ErrMaxBytesExceeded) {
			t.Fatalf("expected ErrMaxBytesExceeded, got %v", err)
		}
	})
}

func TestPostgres_BulkheadCapacityAndRejection(t *testing.T) {
	client := postgres.NewClient(nil, nil)

	blockChan := make(chan struct{})
	pool := &fakeDBPool{
		queryFn: func(ctx context.Context, sql string, readOnly bool, args ...any) (postgres.RowReader, error) {
			select {
			case <-blockChan:
				return &fakeRowReader{cols: []string{"ok"}, data: [][]any{{1}}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	// Bulkhead: Max 1 active concurrent, Max 1 queued
	client.RegisterTarget("target-db", pool, 1, 1)
	client.RegisterNamedQuery(postgres.NamedQuery{
		Name: "slow_query",
		SQL:  "SELECT pg_sleep(10)",
	})

	// 1. First query acquires active slot
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = client.ExecuteNamedQuery(context.Background(), &postgres.QueryRequest{TargetID: "target-db", QueryName: "slow_query"}, nil)
	}()
	time.Sleep(10 * time.Millisecond)

	// 2. Second query enters queue
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = client.ExecuteNamedQuery(context.Background(), &postgres.QueryRequest{TargetID: "target-db", QueryName: "slow_query"}, nil)
	}()
	time.Sleep(10 * time.Millisecond)

	// 3. Third query exceeds both active slot and queue capacity -> must immediately reject
	req := &postgres.QueryRequest{
		TargetID:  "target-db",
		QueryName: "slow_query",
	}
	_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
	if !errors.Is(err, postgres.ErrBulkheadExhausted) {
		t.Fatalf("expected ErrBulkheadExhausted on saturated bulkhead, got %v", err)
	}

	// Clean up blocked goroutines
	close(blockChan)
	wg.Wait()
}

func TestPostgres_ReadOnlyFlag(t *testing.T) {
	client := postgres.NewClient(nil, nil)
	pool := &fakeDBPool{}
	client.RegisterTarget("target-db", pool, 10, 10)

	client.RegisterNamedQuery(postgres.NamedQuery{
		Name:     "read_only_report",
		SQL:      "SELECT count(*) FROM audit",
		ReadOnly: true,
	})

	req := &postgres.QueryRequest{
		TargetID:  "target-db",
		QueryName: "read_only_report",
	}
	_, err := client.ExecuteNamedQuery(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !pool.lastReadOnly {
		t.Fatalf("expected readOnly flag to be passed as true to pool")
	}
}
