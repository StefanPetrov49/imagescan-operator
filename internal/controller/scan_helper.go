package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// scanID returns a stable ID for one image within one ImageScan.
// Same inputs always give the same ID, which keeps reconcile idempotent.
func scanID(scanUID types.UID, image string) string {
	sum := sha256.Sum256([]byte(string(scanUID) + "/" + image))
	return hex.EncodeToString(sum[:])[:16]
}

// isTerminal reports whether an ImageScan is finished and needs no more work.
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

var severityOrder = []securityv1alpha1.Severity{
	securityv1alpha1.SeverityUnknown,
	securityv1alpha1.SeverityLow,
	securityv1alpha1.SeverityMedium,
	securityv1alpha1.SeverityHigh,
	securityv1alpha1.SeverityCritical,
}

// severitiesFrom expands a minimum severity: MEDIUM -> "MEDIUM,HIGH,CRITICAL".
func severitiesFrom(min securityv1alpha1.Severity) string {
	for i, s := range severityOrder {
		if s == min {
			parts := make([]string, 0, len(severityOrder)-i)
			for _, sev := range severityOrder[i:] {
				parts = append(parts, string(sev))
			}
			return strings.Join(parts, ",")
		}
	}
	return ""
}

// jobOutcome maps a Job's terminal condition to a scan phase.
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
