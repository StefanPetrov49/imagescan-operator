package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/StefanPetrov49/imagescan-operator/internal/results"
)

func main() {
	dir := flag.String("results-dir", "/data", "directory holding the reports")
	id := flag.String("id", "", "scan ID")
	imageScan := flag.String("imagescan", "", "owning ImageScan name")
	image := flag.String("image", "", "scanned image reference")
	minSev := flag.String("min-severity", "", "minSeverity used for the scan")
	flag.Parse()

	if !results.ValidID(*id) {
		log.Fatalf("invalid scan id %q", *id)
	}
	f, err := os.Open(filepath.Join(*dir, results.ReportFile(*id)))
	if err != nil {
		log.Fatalf("opening report: %v", err)
	}
	defer f.Close()

	s, err := results.Summarize(f, *id, *imageScan, *image, *minSev)
	if err != nil {
		log.Fatal(err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := results.WriteFileAtomic(filepath.Join(*dir, results.SummaryFile(*id)), data); err != nil {
		log.Fatalf("writing summary: %v", err)
	}
	log.Printf("summary written: %s, %d vulnerabilities", *image, s.Vulnerabilities.Total)
}
