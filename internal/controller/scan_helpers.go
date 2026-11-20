package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// scanID returns a stable ID for one image within one ImageScan.
// Same inputs always give the same ID, which keeps reconcile idempotent, and the result
// (16 lowercase hex characters) is safe to use in Job and file names.
func scanID(scanUID types.UID, image string) string {
	sum := sha256.Sum256([]byte(string(scanUID) + "/" + image))
	return hex.EncodeToString(sum[:])[:16]
}

// isTerminal reports whether a phase is final: the scan needs no more work.
func isTerminal(p securityv1alpha1.ScanPhase) bool {
	switch p {
	case securityv1alpha1.PhaseSucceeded,
		securityv1alpha1.PhasePartiallyFailed,
		securityv1alpha1.PhaseFailed:
		return true
	}
	return false
}

// overallPhase derives the ImageScan phase from its per-image scans.
func overallPhase(scans []securityv1alpha1.ImageScanResult) securityv1alpha1.ScanPhase {
	var succeeded, failed int
	for _, s := range scans {
		switch s.Phase {
		case securityv1alpha1.PhaseSucceeded:
			succeeded++
		case securityv1alpha1.PhaseFailed:
			failed++
		default: // Pending or Running
			return securityv1alpha1.PhaseRunning
		}
	}
	switch {
	case failed == 0:
		return securityv1alpha1.PhaseSucceeded
	case succeeded == 0:
		return securityv1alpha1.PhaseFailed
	default:
		return securityv1alpha1.PhasePartiallyFailed
	}
}

// hasPending reports whether any scan is still waiting for its Job.
func hasPending(scans []securityv1alpha1.ImageScanResult) bool {
	for _, s := range scans {
		if s.Phase == securityv1alpha1.PhasePending {
			return true
		}
	}
	return false
}

// severityOrder lists Trivy's severities from lowest to highest.
var severityOrder = []securityv1alpha1.Severity{
	securityv1alpha1.SeverityUnknown,
	securityv1alpha1.SeverityLow,
	securityv1alpha1.SeverityMedium,
	securityv1alpha1.SeverityHigh,
	securityv1alpha1.SeverityCritical,
}

// severitiesFrom expands a minimum severity into Trivy's list: MEDIUM -> "MEDIUM,HIGH,CRITICAL".
func severitiesFrom(minSeverity securityv1alpha1.Severity) string {
	for i, s := range severityOrder {
		if s == minSeverity {
			parts := make([]string, 0, len(severityOrder)-i)
			for _, sev := range severityOrder[i:] {
				parts = append(parts, string(sev))
			}
			return strings.Join(parts, ",")
		}
	}
	return ""
}

// jobOutcome maps a Job's terminal condition to a scan phase. The verdict comes from the
// conditions, not from the failed counter: failed=1 can mean "retrying" with backoffLimit 1.
func jobOutcome(job *batchv1.Job) (securityv1alpha1.ScanPhase, string) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return securityv1alpha1.PhaseSucceeded, ""
		case batchv1.JobFailed:
			return securityv1alpha1.PhaseFailed, c.Reason + ": " + c.Message
		}
	}
	return securityv1alpha1.PhaseRunning, ""
}

// finishTime returns when a finished Job ended, whether it succeeded or failed.
func finishTime(job *batchv1.Job) *metav1.Time {
	if job.Status.CompletionTime != nil {
		return job.Status.CompletionTime
	}
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			t := c.LastTransitionTime
			return &t
		}
	}
	return nil
}

// scanDuration formats how long a finished scan took, or "" if unknown.
func scanDuration(res *securityv1alpha1.ImageScanResult) string {
	if res.StartTime == nil || res.CompletionTime == nil {
		return ""
	}
	return res.CompletionTime.Sub(res.StartTime.Time).Round(time.Second).String()
}

// lastLine returns the last non-empty line of s, shortened to at most limit bytes.
func lastLine(s string, limit int) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}
