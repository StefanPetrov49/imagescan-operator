package controller

import (
	"regexp"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// Idempotency depends on IDs being stable; Job names depend on them being DNS-safe.
func TestScanID(t *testing.T) {
	a := scanID("uid-1", "nginx:1.25")
	if a != scanID("uid-1", "nginx:1.25") {
		t.Fatal("scanID must be deterministic: same inputs, same ID")
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) {
		t.Fatalf("scanID %q is not 16 lowercase hex chars (needed for Job names)", a)
	}
	if a == scanID("uid-2", "nginx:1.25") {
		t.Error("different ImageScans must get different IDs")
	}
	if a == scanID("uid-1", "redis:7") {
		t.Error("different images must get different IDs")
	}
}

func TestSeveritiesFrom(t *testing.T) {
	cases := map[securityv1alpha1.Severity]string{
		"UNKNOWN":  "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"MEDIUM":   "MEDIUM,HIGH,CRITICAL",
		"CRITICAL": "CRITICAL",
		"":         "",
		"BOGUS":    "",
	}
	for in, want := range cases {
		if got := severitiesFrom(in); got != want {
			t.Errorf("severitiesFrom(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOverallPhase(t *testing.T) {
	const (
		pending   = securityv1alpha1.PhasePending
		running   = securityv1alpha1.PhaseRunning
		succeeded = securityv1alpha1.PhaseSucceeded
		failed    = securityv1alpha1.PhaseFailed
	)
	scans := func(ps ...securityv1alpha1.ScanPhase) []securityv1alpha1.ImageScanResult {
		out := make([]securityv1alpha1.ImageScanResult, len(ps))
		for i, p := range ps {
			out[i].Phase = p
		}
		return out
	}
	cases := []struct {
		name string
		in   []securityv1alpha1.ImageScanResult
		want securityv1alpha1.ScanPhase
	}{
		{"pending means running", scans(succeeded, pending), running},
		{"running means running", scans(failed, running), running},
		{"all succeeded", scans(succeeded, succeeded), succeeded},
		{"all failed", scans(failed, failed), failed},
		{"mix", scans(succeeded, failed), securityv1alpha1.PhasePartiallyFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := overallPhase(c.in); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestIsTerminal(t *testing.T) {
	for p, want := range map[securityv1alpha1.ScanPhase]bool{
		"": false, securityv1alpha1.PhasePending: false, securityv1alpha1.PhaseRunning: false,
		securityv1alpha1.PhaseSucceeded: true, securityv1alpha1.PhasePartiallyFailed: true, securityv1alpha1.PhaseFailed: true,
	} {
		if got := isTerminal(p); got != want {
			t.Errorf("isTerminal(%q) = %v, want %v", p, got, want)
		}
	}
}

// The verdict comes from conditions, not from the failed counter (a retry may still succeed).
func TestJobOutcome(t *testing.T) {
	cond := func(typ batchv1.JobConditionType, status corev1.ConditionStatus) batchv1.JobCondition {
		return batchv1.JobCondition{Type: typ, Status: status, Reason: "DeadlineExceeded", Message: "too slow"}
	}

	retrying := &batchv1.Job{Status: batchv1.JobStatus{Failed: 1}}
	if phase, _ := jobOutcome(retrying); phase != securityv1alpha1.PhaseRunning {
		t.Errorf("failed=1 without a Failed condition must still be Running, got %s", phase)
	}

	done := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{cond(batchv1.JobComplete, corev1.ConditionTrue)}}}
	if phase, _ := jobOutcome(done); phase != securityv1alpha1.PhaseSucceeded {
		t.Errorf("Complete=True must be Succeeded, got %s", phase)
	}

	dead := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{cond(batchv1.JobFailed, corev1.ConditionTrue)}}}
	phase, msg := jobOutcome(dead)
	if phase != securityv1alpha1.PhaseFailed || !strings.Contains(msg, "DeadlineExceeded") {
		t.Errorf("Failed=True must be Failed with the reason, got %s / %q", phase, msg)
	}

	notYet := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{cond(batchv1.JobFailed, corev1.ConditionFalse)}}}
	if phase, _ := jobOutcome(notYet); phase != securityv1alpha1.PhaseRunning {
		t.Errorf("Failed=False must still be Running, got %s", phase)
	}
}
func TestLastLine(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"", 50, ""},
		{"one line", 50, "one line"},
		{"INFO downloading DB\nFATAL unable to pull image\n", 50, "FATAL unable to pull image"},
		{"0123456789", 5, "01234..."},
	}
	for _, c := range cases {
		if got := lastLine(c.in, c.limit); got != c.want {
			t.Errorf("lastLine(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}
