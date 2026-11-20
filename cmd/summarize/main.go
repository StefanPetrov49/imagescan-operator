// Command summarize runs after Trivy in each scan Job: it reads the full report and writes
// a small <id>.summary.json next to it. The summary only exists for completed scans.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/StefanPetrov49/imagescan-operator/internal/results"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir := flag.String("results-dir", "/data", "directory holding the reports")
	id := flag.String("id", "", "scan ID")
	imageScan := flag.String("imagescan", "", "owning ImageScan name")
	image := flag.String("image", "", "scanned image reference")
	minSev := flag.String("min-severity", "", "minSeverity used for the scan")
	flag.Parse()

	if !results.ValidID(*id) {
		return fmt.Errorf("invalid scan id %q", *id)
	}
	f, err := os.Open(filepath.Join(*dir, results.ReportFile(*id)))
	if err != nil {
		return fmt.Errorf("opening report: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only: a failed Close loses nothing

	s, err := results.Summarize(f, *id, *imageScan, *image, *minSev)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := results.WriteFileAtomic(filepath.Join(*dir, results.SummaryFile(*id)), data); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}
	log.Printf("Summary written: %s, %d vulnerabilities", *image, s.Vulnerabilities.Total)
	return nil
}
