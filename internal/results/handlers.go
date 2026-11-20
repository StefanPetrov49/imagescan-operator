package results

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
)

const (
	defaultLimit = 50
	maxLimit     = 500
)

// ListResponse is the body of GET /scans.
type ListResponse struct {
	Items  []Summary `json:"items"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
}

// NewHandler wires the HTTP routes to the store.
func NewHandler(store *Store, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /scans", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, err := intParam(q.Get("limit"), defaultLimit)
		if err != nil || limit < 1 || limit > maxLimit {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be between 1 and %d", maxLimit))
			return
		}
		offset, err := intParam(q.Get("offset"), 0)
		if err != nil || offset < 0 {
			writeError(w, http.StatusBadRequest, "offset must be 0 or more")
			return
		}

		all, err := store.List(q.Get("image"))
		if err != nil {
			log.Error("listing scans", "err", err)
			writeError(w, http.StatusInternalServerError, "cannot read scan results")
			return
		}

		page := []Summary{}
		if offset < len(all) {
			page = all[offset:min(offset+limit, len(all))]
		}
		writeJSON(w, http.StatusOK, ListResponse{Items: page, Total: len(all), Limit: limit, Offset: offset})
	})

	mux.HandleFunc("GET /scans/{id}", func(w http.ResponseWriter, r *http.Request) {
		f, err := store.OpenReport(r.PathValue("id"))
		switch {
		case errors.Is(err, ErrInvalidID):
			writeError(w, http.StatusBadRequest, "invalid scan id")
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "scan not found")
		case err != nil:
			log.Error("opening report", "err", err)
			writeError(w, http.StatusInternalServerError, "cannot read scan result")
		default:
			defer func() { _ = f.Close() }() // read-only: a failed Close loses nothing
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.Copy(w, f); err != nil {
				log.Warn("streaming report", "err", err) // usually: client disconnected
			}
		}
	})

	return mux
}

func intParam(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	return strconv.Atoi(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
