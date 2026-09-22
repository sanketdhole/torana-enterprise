package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// StartHTTPDashboard launches the web dashboard.
func StartHTTPDashboard(addr string, state *PlatformState) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"config_version": state.configVersion.Load(),
			"public_key_hex": state.PublicKeyHex(),
			"nodes":          state.GetNodes(),
			"snapshot":       state.CurrentSnapshot(),
		})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		nodes := state.GetNodes()
		snap := state.CurrentSnapshot()
		currentVer := state.configVersion.Load()
		pubKeyHex := state.PublicKeyHex()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="2">
  <title>Torana Mock Platform - Control Plane Dashboard</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    h1 { font-size: 24px; color: #f0f6fc; }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      background: var(--border);
    }
    .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); border: 1px solid var(--success); }
    .badge-warning { background: rgba(210, 153, 34, 0.2); color: var(--warning); border: 1px solid var(--warning); }
    .badge-danger { background: rgba(248, 81, 73, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .card h3 { font-size: 14px; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .card .value { font-size: 24px; font-weight: 700; color: #f0f6fc; }
    .card .meta { font-size: 12px; color: var(--text-muted); margin-top: 4px; word-break: break-all; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-weight: 600; background: rgba(255,255,255,0.02); }
    tr:hover { background: rgba(255,255,255,0.02); }
    .code { font-family: monospace; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    .empty { padding: 32px; text-align: center; color: var(--text-muted); }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Torana Mock Platform (Control Plane)</h1>
      <p style="color: var(--text-muted); font-size: 13px;">Local gRPC Control Plane with Ed25519 Signing & Hot-Reload</p>
    </div>
    <div>
      <span class="badge badge-success">LIVE (Auto-refresh 2s)</span>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h3>Active Config Version</h3>
      <div class="value">v` + fmt.Sprintf("%d", currentVer) + `</div>
      <div class="meta">Routes: ` + fmt.Sprintf("%d", len(snap.Routes)) + ` | Upstreams: ` + fmt.Sprintf("%d", len(snap.Upstreams)) + `</div>
    </div>
    <div class="card">
      <h3>Connected Pods</h3>
      <div class="value">` + fmt.Sprintf("%d", len(nodes)) + `</div>
      <div class="meta">Gateway Data Plane Instances</div>
    </div>
    <div class="card">
      <h3>Dev Ed25519 Public Key</h3>
      <div class="code" style="font-size: 11px;">` + pubKeyHex[:min(len(pubKeyHex), 24)] + `...` + pubKeyHex[max(0, len(pubKeyHex)-16):] + `</div>
      <div class="meta">Verifies signed snapshot payloads</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <h3>Connected Gateway Instances</h3>
    <table>
      <thead>
        <tr>
          <th>Node ID</th>
          <th>Namespace</th>
          <th>Applied Config Version</th>
          <th>Ack / Nack Status</th>
          <th>Last Heartbeat</th>
          <th>Connected For</th>
        </tr>
      </thead>
      <tbody>`

		if len(nodes) == 0 {
			html += `<tr><td colspan="6" class="empty">No gateway instances connected yet. Start <code>gateway-data --platform-url=localhost:9090</code></td></tr>`
		} else {
			for _, n := range nodes {
				statusBadge := `<span class="badge badge-warning">PENDING</span>`
				if n.LastAckStatus == "ACK" {
					statusBadge = `<span class="badge badge-success">ACK (v` + fmt.Sprintf("%d", n.CurrentConfigVersion) + `)</span>`
				} else if len(n.LastAckStatus) >= 4 && n.LastAckStatus[:4] == "NACK" {
					statusBadge = `<span class="badge badge-danger">` + n.LastAckStatus + `</span>`
				}

				html += `<tr>
          <td><strong>` + n.NodeID + `</strong></td>
          <td><span class="code">` + n.Namespace + `</span></td>
          <td><span class="code">v` + fmt.Sprintf("%d", n.CurrentConfigVersion) + `</span></td>
          <td>` + statusBadge + `</td>
          <td>` + time.Since(n.LastHeartbeat).Truncate(time.Second).String() + ` ago</td>
          <td>` + time.Since(n.ConnectedAt).Truncate(time.Second).String() + `</td>
        </tr>`
			}
		}

		html += `</tbody>
    </table>
  </div>

  <div class="card">
    <h3>Active Routes in Snapshot</h3>
    <table>
      <thead>
        <tr>
          <th>Route ID</th>
          <th>Method</th>
          <th>Path</th>
          <th>Upstream Target</th>
        </tr>
      </thead>
      <tbody>`

		for _, r := range snap.Routes {
			html += `<tr>
        <td><strong>` + r.Id + `</strong></td>
        <td><span class="code">` + r.Method + `</span></td>
        <td><span class="code">` + r.Path + `</span></td>
        <td>` + r.UpstreamId + `</td>
      </tr>`
		}

		html += `</tbody>
    </table>
  </div>
</div>
</body>
</html>`

		_, _ = w.Write([]byte(html))
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return server.ListenAndServe()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
