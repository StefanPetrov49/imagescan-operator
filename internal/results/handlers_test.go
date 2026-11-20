package results

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeScan(t *testing.T, dir string, s Summary, withSummary bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ReportFile(s.ID)), []byte(`{"report":"`+s.ID+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if withSummary {
		data, _ := json.Marshal(s)
		if err := os.WriteFile(filepath.Join(dir, SummaryFile(s.ID)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()

	base := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	writeScan(t, dir, Summary{ID: "aaaaaaaaaaaaaaaa", Image: "nginx:1.25", ScannedAt: base}, true)
	writeScan(t, dir, Summary{ID: "bbbbbbbbbbbbbbbb", Image: "redis:7", ScannedAt: base.Add(time.Minute)}, true)
	writeScan(t, dir, Summary{ID: "cccccccccccccccc", Image: "nginx:1.27", ScannedAt: base.Add(2 * time.Minute)}, true)
	writeScan(t, dir, Summary{ID: "dddddddddddddddd", Image: "old:1"}, false) // report, no summary
	_ = os.Mkdir(filepath.Join(dir, "trivy-cache"), 0o755)                    // must be ignored
	_ = os.WriteFile(filepath.Join(dir, "eeeeeeeeeeeeeeee.summary.json.tmp"), []byte("{half"), 0o644)

	store, err := NewStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(NewHandler(store, slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func listIDs(t *testing.T, srv *httptest.Server, query string) ([]string, int) {
	t.Helper()
	code, body := get(t, srv.URL+"/scans"+query)
	if code != http.StatusOK {
		t.Fatalf("GET /scans%s = %d: %s", query, code, body)
	}
	var lr ListResponse
	if err := json.Unmarshal([]byte(body), &lr); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(lr.Items))
	for _, s := range lr.Items {
		ids = append(ids, s.ID)
	}
	return ids, lr.Total
}

func TestListScans(t *testing.T) {
	srv := newTestServer(t)
	cases := []struct {
		query     string
		wantIDs   []string
		wantTotal int
	}{
		{"", []string{"cccccccccccccccc", "bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa"}, 3}, // newest first, only completed scans
		{"?image=nginx", []string{"cccccccccccccccc", "aaaaaaaaaaaaaaaa"}, 2},
		{"?image=nginx:1.25", []string{"aaaaaaaaaaaaaaaa"}, 1},
		{"?limit=1&offset=1", []string{"bbbbbbbbbbbbbbbb"}, 3},
		{"?offset=10", []string{}, 3},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			ids, total := listIDs(t, srv, c.query)
			if !reflect.DeepEqual(ids, c.wantIDs) || total != c.wantTotal {
				t.Errorf("got %v (total %d), want %v (total %d)", ids, total, c.wantIDs, c.wantTotal)
			}
		})
	}
}

func TestListRejectsBadParams(t *testing.T) {
	srv := newTestServer(t)
	for _, q := range []string{"?limit=0", "?limit=abc", "?limit=501", "?offset=-1"} {
		if code, _ := get(t, srv.URL+"/scans"+q); code != http.StatusBadRequest {
			t.Errorf("GET /scans%s = %d, want 400", q, code)
		}
	}
}

func TestGetScan(t *testing.T) {
	srv := newTestServer(t)

	code, body := get(t, srv.URL+"/scans/aaaaaaaaaaaaaaaa")
	if code != http.StatusOK || !strings.Contains(body, "aaaaaaaaaaaaaaaa") {
		t.Errorf("existing scan: got %d %q", code, body)
	}
	if code, _ := get(t, srv.URL+"/scans/dddddddddddddddd"); code != http.StatusNotFound {
		t.Errorf("report without summary: got %d, want 404", code)
	}
	for _, id := range []string{"hello", "AAAAAAAAAAAAAAAA"} {
		if code, _ := get(t, srv.URL+"/scans/"+id); code != http.StatusBadRequest {
			t.Errorf("id %q: got %d, want 400", id, code)
		}
	}
	// Path traversal: whatever the router does with it, it must never serve a file.
	code, body = get(t, srv.URL+"/scans/..%2F..%2Fetc%2Fpasswd")
	if code == http.StatusOK || strings.Contains(body, "root:") {
		t.Errorf("path traversal must not succeed: got %d %q", code, body)
	}
}
