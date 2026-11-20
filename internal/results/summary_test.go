package results

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidID(t *testing.T) {
	for _, id := range []string{"0123456789abcdef", "cee3377c85f8858f"} {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0",
		"0123456789abcdeg", "../../etc/passwd", "..%2F..%2Fetc"} {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}

const sampleReport = `{
  "CreatedAt": "2026-11-19T23:15:38Z",
  "Metadata": {"OS": {"Family": "debian", "Name": "12.5"}, "RepoDigests": ["nginx@sha256:abc"]},
  "Results": [
    {"Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"}]},
    {"Vulnerabilities": [{"Severity": "MEDIUM"}, {"Severity": "SOMETHING-NEW"}]},
    {"Target": "a result without vulnerabilities"}
  ],
  "FieldsWeDontModel": {"ignored": true}
}`

func TestSummarize(t *testing.T) {
	s, err := Summarize(strings.NewReader(sampleReport), "0123456789abcdef", "scan-a", "nginx:1.25", "MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
	want := Counts{Critical: 1, High: 2, Medium: 1, Unknown: 1, Total: 5}
	if s.Vulnerabilities != want {
		t.Errorf("counts = %+v, want %+v", s.Vulnerabilities, want)
	}
	if s.OS != "debian 12.5" || s.Digest != "nginx@sha256:abc" || s.Image != "nginx:1.25" || s.ImageScan != "scan-a" {
		t.Errorf("unexpected summary fields: %+v", s)
	}
	if !s.ScannedAt.Equal(time.Date(2026, 11, 19, 23, 15, 38, 0, time.UTC)) {
		t.Errorf("scannedAt = %v", s.ScannedAt)
	}
}

func TestSummarizeRejectsGarbage(t *testing.T) {
	if _, err := Summarize(strings.NewReader("not json"), "0123456789abcdef", "", "", ""); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.summary.json")
	if err := WriteFileAtomic(path, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "hello" {
		t.Errorf("content = %q", data)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("temp file was left behind")
	}
}
