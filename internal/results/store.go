package results

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"slices"
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
	log  *slog.Logger
}

// NewStore opens dir for reading. log reports summaries that can't be read.
func NewStore(dir string, log *slog.Logger) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, log: log}, nil
}

// Close releases the directory handle.
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
			if !errors.Is(err, fs.ErrNotExist) { // not exist = removed meanwhile: fine
				s.log.Warn("Skipping unreadable summary", "file", e.Name(), "err", err)
			}
			continue
		}
		var sum Summary
		if err := json.Unmarshal(data, &sum); err != nil {
			s.log.Warn("Skipping corrupt summary", "file", e.Name(), "err", err)
			continue
		}
		if strings.HasPrefix(sum.Image, prefix) {
			out = append(out, sum)
		}
	}
	slices.SortFunc(out, func(a, b Summary) int {
		if c := b.ScannedAt.Compare(a.ScannedAt); c != 0 {
			return c // newest first
		}
		return strings.Compare(a.ID, b.ID) // stable order for equal timestamps
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
