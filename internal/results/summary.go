package results

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ValidID reports whether id has the exact shape of a scan ID (16 lowercase hex chars).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ReportFile is the file name of the full Trivy report of a scan.
func ReportFile(id string) string { return id + ".json" }

// SummaryFile is the file name of a scan's summary. It only exists for completed scans.
func SummaryFile(id string) string { return id + ".summary.json" }

// Summary is the small per-scan record served by GET /scans.
type Summary struct {
	ID              string    `json:"id"`
	ImageScan       string    `json:"imageScan"`
	Image           string    `json:"image"`
	Digest          string    `json:"digest,omitempty"`
	ScannedAt       time.Time `json:"scannedAt"`
	OS              string    `json:"os,omitempty"`
	MinSeverity     string    `json:"minSeverity,omitempty"`
	Vulnerabilities Counts    `json:"vulnerabilities"`
}

// Counts are vulnerability counts by Trivy severity. The keys match Trivy's severity names;
// changing them would break summaries already stored on the volume.
type Counts struct {
	Critical int `json:"CRITICAL"`
	High     int `json:"HIGH"`
	Medium   int `json:"MEDIUM"`
	Low      int `json:"LOW"`
	Unknown  int `json:"UNKNOWN"`
	Total    int `json:"total"`
}

// trivyReport is the small subset of Trivy's JSON report that we need.
type trivyReport struct {
	CreatedAt time.Time `json:"CreatedAt"`
	Metadata  struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Summarize reads a Trivy JSON report and builds its Summary.
func Summarize(r io.Reader, id, imageScan, image, minSeverity string) (Summary, error) {
	var rep trivyReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return Summary{}, fmt.Errorf("decoding trivy report: %w", err)
	}
	s := Summary{ID: id, ImageScan: imageScan, Image: image, ScannedAt: rep.CreatedAt, MinSeverity: minSeverity}
	if len(rep.Metadata.RepoDigests) > 0 {
		s.Digest = rep.Metadata.RepoDigests[0]
	}
	if osInfo := rep.Metadata.OS; osInfo != nil {
		s.OS = strings.TrimSpace(osInfo.Family + " " + osInfo.Name)
	}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			switch v.Severity {
			case "CRITICAL":
				s.Vulnerabilities.Critical++
			case "HIGH":
				s.Vulnerabilities.High++
			case "MEDIUM":
				s.Vulnerabilities.Medium++
			case "LOW":
				s.Vulnerabilities.Low++
			default:
				s.Vulnerabilities.Unknown++
			}
			s.Vulnerabilities.Total++
		}
	}
	return s, nil
}

// WriteFileAtomic writes via a temp file + rename, so readers never see a half-written file.
func WriteFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
