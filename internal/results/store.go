package results

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
)

var (
	// ErrInvalidID: the id does not have the shape of a scan ID.
	ErrInvalidID = errors.New("invalid scan id")
	// ErrNotFound: no completed scan (= no summary) with this id.
	ErrNotFound = errors.New("scan not found")
)

// Store reads scan results from one directory. All access goes through os.Root,
// so no file outside that directory can ever be opened, even by mistake.
type Store struct {
	root *os.Root
}

func NewStore(dir string) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) Close() error { return s.root.Close() }

// List returns summaries of completed scans whose image starts with prefix, newest first.
func (s *Store) List(prefix string) ([]Summary, error) {
	entries, err := fs.ReadDir(s.root.FS(), ".")
	if err != nil {
		return nil, err
	}
	out := []Summary{}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".summary.json")
		if !ok || e.IsDir() || !ValidID(id) {
			continue // reports, .tmp files, trivy-cache/, anything unexpected
		}
		data, err := fs.ReadFile(s.root.FS(), e.Name())
		if err != nil {
			continue // removed meanwhile
		}
		var sum Summary
		if err := json.Unmarshal(data, &sum); err != nil {
			continue
		}
		if strings.HasPrefix(sum.Image, prefix) {
			out = append(out, sum)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ScannedAt.Equal(out[j].ScannedAt) {
			return out[i].ScannedAt.After(out[j].ScannedAt)
		}
		return out[i].ID < out[j].ID // stable order for equal timestamps
	})
	return out, nil
}

// OpenReport opens the full Trivy report of a completed scan.
func (s *Store) OpenReport(id string) (*os.File, error) {
	if !ValidID(id) {
		return nil, ErrInvalidID
	}
	if _, err := s.root.Stat(SummaryFile(id)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound // no summary = not a completed scan
		}
		return nil, err
	}
	f, err := s.root.Open(ReportFile(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}
