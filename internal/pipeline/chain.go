package pipeline

import (
	"fmt"
)

// Chain executes an ordered list of Filters.
type Chain struct {
	filters []Filter
}

// NewChain creates a new filter execution chain.
func NewChain(filters ...Filter) *Chain {
	return &Chain{
		filters: filters,
	}
}

// Execute runs all filters in order against the RequestContext.
// Halts execution on the first error encountered (fail-closed).
func (c *Chain) Execute(ctx *RequestContext) error {
	for _, f := range c.filters {
		select {
		case <-ctx.Ctx.Done():
			return ctx.Ctx.Err()
		default:
		}

		if err := f.Execute(ctx); err != nil {
			return fmt.Errorf("filter %q failed: %w", f.Name(), err)
		}
	}
	return nil
}

// Filters returns a slice of all configured filters.
func (c *Chain) Filters() []Filter {
	return c.filters
}
