package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
)

// RowReader abstracts scanning rows from a query execution.
type RowReader interface {
	Columns() []string
	Next() bool
	Values() ([]any, error)
	Err() error
	Close()
}

// DBPool defines the database pool operations required by Client.
type DBPool interface {
	Query(ctx context.Context, sql string, readOnly bool, args ...any) (RowReader, error)
	Close()
}

// pgxPoolAdapter wraps *pgxpool.Pool to implement DBPool.
type pgxPoolAdapter struct {
	pool *pgxpool.Pool
}

// NewPGXPoolAdapter creates a DBPool adapter around a pgx connection pool.
func NewPGXPoolAdapter(pool *pgxpool.Pool) DBPool {
	return &pgxPoolAdapter{pool: pool}
}

func (a *pgxPoolAdapter) Query(ctx context.Context, sql string, readOnly bool, args ...any) (RowReader, error) {
	if readOnly {
		tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		return &pgxRowsAdapter{rows: rows, tx: tx}, nil
	}

	rows, err := a.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRowsAdapter{rows: rows}, nil
}

func (a *pgxPoolAdapter) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}

type pgxRowsAdapter struct {
	rows pgx.Rows
	tx   pgx.Tx
}

func (r *pgxRowsAdapter) Columns() []string {
	fields := r.rows.FieldDescriptions()
	cols := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = f.Name
	}
	return cols
}

func (r *pgxRowsAdapter) Next() bool {
	return r.rows.Next()
}

func (r *pgxRowsAdapter) Values() ([]any, error) {
	return r.rows.Values()
}

func (r *pgxRowsAdapter) Err() error {
	return r.rows.Err()
}

func (r *pgxRowsAdapter) Close() {
	r.rows.Close()
	if r.tx != nil {
		_ = r.tx.Rollback(context.Background())
	}
}

// Client manages named query execution, connection pools, authz, and bulkheads.
type Client struct {
	mu          sync.RWMutex
	pools       map[string]DBPool
	bulkheads   map[string]*Bulkhead
	queries     map[string]*NamedQuery
	authzEngine *authz.PolicyEngine
	logger      *slog.Logger
}

// NewClient creates a new Postgres egress client.
func NewClient(authzEngine *authz.PolicyEngine, logger *slog.Logger) *Client {
	return &Client{
		pools:       make(map[string]DBPool),
		bulkheads:   make(map[string]*Bulkhead),
		queries:     make(map[string]*NamedQuery),
		authzEngine: authzEngine,
		logger:      logger,
	}
}

// RegisterNamedQuery registers a pre-configured named query into the catalog.
func (c *Client) RegisterNamedQuery(q NamedQuery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries[q.Name] = &q
}

// RegisterTarget registers a database pool and configures its bulkhead.
func (c *Client) RegisterTarget(targetID string, pool DBPool, maxConcurrent, maxQueue int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pools[targetID] = pool
	c.bulkheads[targetID] = NewBulkhead(maxConcurrent, maxQueue)
}

// RegisterTargetPool connects a pgxpool.Pool and registers the target.
func (c *Client) RegisterTargetPool(ctx context.Context, cfg TargetConfig) error {
	poolCfg, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return fmt.Errorf("invalid postgres conn string for target %q: %w", cfg.TargetID, err)
	}

	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = cfg.MinConns
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("failed to create pgx pool for target %q: %w", cfg.TargetID, err)
	}

	c.RegisterTarget(cfg.TargetID, NewPGXPoolAdapter(pool), cfg.BulkheadLimit, cfg.BulkheadQueueSize)
	return nil
}

// ExecuteNamedQuery executes a registered named query with parameter coercion, authz check,
// bulkhead slot acquisition, and row/byte limits.
func (c *Client) ExecuteNamedQuery(ctx context.Context, req *QueryRequest, env *pipeline.Envelope) (*QueryResult, error) {
	startTime := time.Now()

	if req == nil || req.QueryName == "" {
		return nil, ErrUnknownNamedQuery
	}

	// 1. Lookup Named Query
	c.mu.RLock()
	query, ok := c.queries[req.QueryName]
	pool, poolOk := c.pools[req.TargetID]
	bulkhead, bhOk := c.bulkheads[req.TargetID]
	c.mu.RUnlock()

	if !ok || query == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownNamedQuery, req.QueryName)
	}
	if !poolOk || pool == nil {
		return nil, fmt.Errorf("%w: %q", ErrTargetNotFound, req.TargetID)
	}

	// 2. Evaluate CEL Authorization Policy on db_query
	if c.authzEngine != nil {
		var ident *authn.Identity
		if env != nil {
			if id, ok := env.Identity.(*authn.Identity); ok {
				ident = id
			}
		}

		headers := make(map[string]string)
		path := ""
		if env != nil {
			path = env.Path
			if env.Headers != nil {
				for k, vv := range env.Headers {
					if len(vv) > 0 {
						headers[k] = vv[0]
					}
				}
			}
		}

		reqAttrs := authz.RequestAttributes{
			Path:    path,
			Method:  "POST",
			Headers: headers,
			Time:    startTime,
		}
		res := authz.Resource{
			Type: authz.ResourceTypeDBQuery,
			ID:   query.Name,
		}
		act := authz.Action{
			Name:   "execute",
			Method: "POST",
		}

		if err := c.authzEngine.Evaluate(ctx, ident, res, act, reqAttrs); err != nil {
			if c.logger != nil {
				c.logger.Debug("db_query execution denied by policy", "query", query.Name, "error", err)
			}
			return nil, ErrUnauthorizedDBQuery
		}
	}

	// 3. Validate and Coerce Typed Parameters
	args := make([]any, 0, len(query.Params))
	for _, spec := range query.Params {
		rawVal := req.Params[spec.Name]
		coerced, err := spec.ValidateAndCoerce(rawVal)
		if err != nil {
			return nil, err
		}
		args = append(args, coerced)
	}

	// 4. Acquire Per-Target Bulkhead Slot
	if bhOk && bulkhead != nil {
		release, err := bulkhead.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
	}

	// 5. Apply Query Timeout
	queryTimeout := query.Timeout
	if queryTimeout <= 0 {
		queryTimeout = 30 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// 6. Execute Query
	rows, err := pool.Query(queryCtx, query.SQL, query.ReadOnly, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres query failed: %w", err)
	}
	defer rows.Close()

	// 7. Read Rows and Enforce Row & Byte Limits
	columns := rows.Columns()
	var (
		resultRows [][]any
		rowCount   int64
		bytesRead  int64
		truncated  bool
	)

	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if query.MaxRows > 0 && rowCount >= query.MaxRows {
			truncated = true
			break
		}

		rowSize := estimateRowBytes(vals)
		if query.MaxBytes > 0 && (bytesRead+rowSize) > query.MaxBytes {
			return nil, ErrMaxBytesExceeded
		}

		bytesRead += rowSize
		resultRows = append(resultRows, vals)
		rowCount++
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return &QueryResult{
		Columns:   columns,
		Rows:      resultRows,
		RowCount:  rowCount,
		BytesRead: bytesRead,
		Duration:  time.Since(startTime),
		Truncated: truncated,
	}, nil
}

// Close closes all registered target database pools.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pool := range c.pools {
		pool.Close()
	}
}

// estimateRowBytes provides a fast heuristic calculation of serialized row size.
func estimateRowBytes(vals []any) int64 {
	var total int64
	for _, v := range vals {
		if v == nil {
			total += 1
			continue
		}
		switch val := v.(type) {
		case string:
			total += int64(len(val))
		case []byte:
			total += int64(len(val))
		case int, int32, int64, float32, float64:
			total += 8
		case bool:
			total += 1
		case time.Time:
			total += 24
		default:
			b, _ := json.Marshal(val)
			total += int64(len(b))
		}
	}
	return total
}
