#!/bin/sh
# entrypoint.sh — Auto-set GOMEMLIMIT from container cgroup v2 memory limit.
#
# When running in Kubernetes or Docker with a memory limit, the Go runtime's
# GC will respect GOMEMLIMIT and trigger GC earlier to avoid OOM kills.
# We set it to 90% of the cgroup limit to leave headroom for non-heap memory
# (goroutine stacks, mmap'd files, OS buffers).
#
# If no cgroup limit is set or GOMEMLIMIT is already configured, this is a no-op.

set -e

if [ "$GOMEMLIMIT" = "0" ] || [ -z "$GOMEMLIMIT" ]; then
  # cgroup v2 (standard in modern Kubernetes)
  if [ -f /sys/fs/cgroup/memory.max ]; then
    LIMIT=$(cat /sys/fs/cgroup/memory.max)
    if [ "$LIMIT" != "max" ] && [ "$LIMIT" -gt 0 ] 2>/dev/null; then
      GOMEMLIMIT=$((LIMIT * 90 / 100))
      export GOMEMLIMIT
      echo "entrypoint: GOMEMLIMIT set to ${GOMEMLIMIT} bytes (90% of cgroup limit ${LIMIT})"
    fi
  # cgroup v1 fallback
  elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    LIMIT=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    # cgroup v1 uses a very large number (>= 2^62) to indicate "no limit"
    if [ "$LIMIT" -lt 4611686018427387904 ] 2>/dev/null; then
      GOMEMLIMIT=$((LIMIT * 90 / 100))
      export GOMEMLIMIT
      echo "entrypoint: GOMEMLIMIT set to ${GOMEMLIMIT} bytes (90% of cgroup v1 limit ${LIMIT})"
    fi
  fi
fi

exec /app/gateway-data "$@"
