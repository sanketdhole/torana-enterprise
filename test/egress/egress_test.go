package egress_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestHTTPClient_Execute(t *testing.T) {
	mockTransport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Header.Get("X-Custom-Header") != "TestValue" {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader("missing custom header")),
				Header:     make(http.Header),
			}
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "ping payload" {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader("unexpected body")),
				Header:     make(http.Header),
			}
		}

		header := make(http.Header)
		header.Set("X-Upstream-Response", "pong")

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"reply":"pong"}`)),
			Header:     header,
		}
	})

	client := egress.NewHTTPClient()
	client.SetTransportForCluster("upstream-test", mockTransport)
	client.SetDefaultTransport(mockTransport)
	defer func() { _ = client.Close() }()

	cluster := &config.UpstreamCluster{
		ID:        "upstream-test",
		Protocol:  "http",
		Endpoints: []string{"http://mock-upstream.local"},
		Timeout:   5 * time.Second,
	}

	headers := make(http.Header)
	headers.Set("X-Custom-Header", "TestValue")

	req := &egress.Request{
		Method:  http.MethodPost,
		Path:    "/test-endpoint",
		Headers: headers,
		Body:    strings.NewReader("ping payload"),
	}

	resp, err := client.Execute(context.Background(), cluster, req)
	if err != nil {
		t.Fatalf("unexpected error executing request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if resp.Headers.Get("X-Upstream-Response") != "pong" {
		t.Errorf("expected header 'pong', got %s", resp.Headers.Get("X-Upstream-Response"))
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"reply":"pong"}` {
		t.Errorf("expected response body '{\"reply\":\"pong\"}', got %s", string(body))
	}
}

func TestRegistry(t *testing.T) {
	reg := egress.NewRegistry()
	defer func() { _ = reg.Close() }()

	client, err := reg.Get("http")
	if err != nil || client == nil {
		t.Fatalf("expected 'http' client, got err: %v", err)
	}

	_, err = reg.Get("non-existent")
	if err == nil {
		t.Fatalf("expected error for non-existent protocol")
	}
}
