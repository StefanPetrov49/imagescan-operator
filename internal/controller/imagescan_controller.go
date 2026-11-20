package controller

import (
	"context"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
	"github.com/StefanPetrov49/imagescan-operator/internal/targeting"
)

const (
	// maxRunningScans limits scan Jobs cluster-wide. All Jobs share one Trivy cache on the
	// results PVC and Trivy locks its cache, so scans run one after another.
	maxRunningScans = 1
	// pendingRecheck is how often an ImageScan that waits for its turn checks again.
	// A finished Job only wakes its own ImageScan, so the others have to poll.
	pendingRecheck = 15 * time.Second
	// conflictRetry is the delay after a status update was based on a stale copy.
	conflictRetry = time.Second
	// maxErrorDetail caps how much of Trivy's error output is copied into the status.
	maxErrorDetail = 300
)

// ImageScanReconciler reconciles ImageScan objects: it resolves the target images once,
// runs one Trivy Job per image (one at a time), records each outcome and deletes the Jobs.
type ImageScanReconciler struct {
	client.Client
	// APIReader reads straight from the API server, without cache lag.
	APIReader client.Reader
	Scheme    *runtime.Scheme

	// Namespace is the operator's own namespace: scan Jobs and the results PVC live here.
	Namespace string
	// Excluded namespaces are never scanned (--excluded-namespaces).
	Excluded map[string]bool
	// ResultsPVC holds the reports, the summaries and the shared Trivy cache.
	ResultsPVC string
	// TrivyImage is the scanner image.
	TrivyImage string
	// SummarizerImage contains /summarize; normally the operator's own image.
	SummarizerImage string
}

// +kubebuilder:rbac:groups=security.stefanpetrov.dev,resources=imagescans,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.stefanpetrov.dev,resources=imagescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces;pods,verbs=get;list;watch

// Jobs only in the operator namespace (a Role, not a ClusterRole): creating a Job means
// creating Pods, and a Pod can mount any Secret of its namespace.
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete,namespace=system

// Reconcile moves an ImageScan one step forward. It is safe to run any number of times.
func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var scan securityv1alpha1.ImageScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch {
	case isTerminal(scan.Status.Phase):
		// Finished (snapshot semantics): only make sure no Jobs are left behind.
		return ctrl.Result{}, r.deleteFinishedJobs(ctx, &scan)
	case scan.Status.Phase == "":
		// First run: resolve the target images once and record them.
		return r.initialize(ctx, &scan)
	default:
		// Running: drive the per-image scans forward.
		return r.progress(ctx, &scan)
	}
}

// initialize resolves the target images and records one Pending scan per image.
func (r *ImageScanReconciler) initialize(ctx context.Context, scan *securityv1alpha1.ImageScan) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	images, err := targeting.FindTargetImages(ctx, r.Client, scan.Spec, r.Excluded)
	if err != nil {
		return ctrl.Result{}, err // probably temporary: controller-runtime retries with backoff
	}

	if len(images) == 0 {
		// Permanent: retrying won't help. (The webhook checked at admission time, but
		// Pods may have disappeared since, or the webhook may have been bypassed.)
		scan.Status.Phase = securityv1alpha1.PhaseFailed
		scan.Status.Message = "no pods match the given selectors"
		return r.updateStatus(ctx, scan)
	}

	scans := make([]securityv1alpha1.ImageScanResult, 0, len(images))
	for _, img := range images {
		scans = append(scans, securityv1alpha1.ImageScanResult{
			ID:    scanID(scan.UID, img),
			Image: img,
			Phase: securityv1alpha1.PhasePending,
		})
	}
	scan.Status.Scans = scans
	scan.Status.Phase = securityv1alpha1.PhaseRunning
	log.Info("Resolved target images", "count", len(images))
	return r.updateStatus(ctx, scan)
}

// progress records finished Jobs, starts the next pending scan when no scan is running,
// saves the status and only then deletes finished Jobs.
func (r *ImageScanReconciler) progress(ctx context.Context, scan *securityv1alpha1.ImageScan) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Step 1: check every scan that has a Job.
	for i := range scan.Status.Scans {
		res := &scan.Status.Scans[i]
		if res.Phase != securityv1alpha1.PhaseRunning {
			continue
		}
		var job batchv1.Job
		err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: jobName(res.ID)}, &job)
		switch {
		case apierrors.IsNotFound(err):
			// Usually cache lag right after creation. Creating again is safe (stable name).
			if err := r.createJob(ctx, scan, *res); err != nil {
				return ctrl.Result{}, err
			}
		case err != nil:
			return ctrl.Result{}, err
		default:
			res.Phase, res.Message = jobOutcome(&job)
			res.StartTime = job.Status.StartTime
			if isTerminal(res.Phase) {
				res.CompletionTime = finishTime(&job)
				if res.Phase == securityv1alpha1.PhaseFailed {
					// Read Trivy's error now: the Pods are deleted together with the Job.
					if detail := r.scannerError(ctx, res.ID); detail != "" {
						res.Message += " | trivy: " + detail
					}
				}
				log.Info("Scan finished", "image", res.Image, "phase", res.Phase, "duration", scanDuration(res))
			}
		}
	}

	// Step 2: start the next pending scan, but only if no scan runs anywhere in the cluster.
	for i := range scan.Status.Scans {
		res := &scan.Status.Scans[i]
		if res.Phase != securityv1alpha1.PhasePending {
			continue
		}
		running, err := r.runningScanJobs(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		if running < maxRunningScans {
			if err := r.createJob(ctx, scan, *res); err != nil {
				return ctrl.Result{}, err
			}
			res.Phase = securityv1alpha1.PhaseRunning
		}
		break // at most one new Job per reconcile
	}

	// Step 3: record first, then clean up. If the status can't be saved, keep the Jobs.
	scan.Status.Phase = overallPhase(scan.Status.Scans)
	if result, err := r.updateStatus(ctx, scan); err != nil || !result.IsZero() {
		return result, err
	}
	if err := r.deleteFinishedJobs(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}

	// Step 4: something still waiting for its turn? Check back later.
	if hasPending(scan.Status.Scans) {
		return ctrl.Result{RequeueAfter: pendingRecheck}, nil
	}
	return ctrl.Result{}, nil
}

// updateStatus saves the status. A conflict means our copy was stale, which is expected
// when reading from a cache, so it is retried shortly instead of being logged as an error.
func (r *ImageScanReconciler) updateStatus(ctx context.Context, scan *securityv1alpha1.ImageScan) (ctrl.Result, error) {
	if err := r.Status().Update(ctx, scan); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: conflictRetry}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// deleteFinishedJobs removes Jobs whose scan reached a final phase. Safe to call repeatedly.
func (r *ImageScanReconciler) deleteFinishedJobs(ctx context.Context, scan *securityv1alpha1.ImageScan) error {
	for _, res := range scan.Status.Scans {
		if !isTerminal(res.Phase) {
			continue
		}
		job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: jobName(res.ID), Namespace: r.Namespace}}
		// Background propagation: without it, deleting a Job through the API orphans its Pods.
		err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
		if client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

// createJob creates the Trivy Job for one scan. AlreadyExists is fine (idempotent).
func (r *ImageScanReconciler) createJob(ctx context.Context, scan *securityv1alpha1.ImageScan,
	res securityv1alpha1.ImageScanResult) error {
	job, err := r.buildTrivyJob(scan, res)
	if err != nil {
		return err
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// runningScanJobs counts unfinished scan Jobs across ALL ImageScans. It reads from the API
// server directly: the cache could still miss a Job created a moment ago.
func (r *ImageScanReconciler) runningScanJobs(ctx context.Context) (int, error) {
	var jobs batchv1.JobList
	if err := r.APIReader.List(ctx, &jobs, client.InNamespace(r.Namespace),
		client.HasLabels{labelScanID}); err != nil {
		return 0, err
	}
	n := 0
	for i := range jobs.Items {
		if phase, _ := jobOutcome(&jobs.Items[i]); phase == securityv1alpha1.PhaseRunning {
			n++
		}
	}
	return n, nil
}

// scannerError returns the last line of Trivy's output from a failed scan Pod (its
// termination message, see TerminationMessagePolicy in buildTrivyJob), or "".
func (r *ImageScanReconciler) scannerError(ctx context.Context, id string) string {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.Namespace), client.MatchingLabels{labelScanID: id}); err != nil {
		return ""
	}
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.InitContainerStatuses {
			if t := cs.State.Terminated; cs.Name == trivyContainerName && t != nil && t.ExitCode != 0 {
				if line := lastLine(t.Message, maxErrorDetail); line != "" {
					return line
				}
			}
		}
	}
	return ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ImageScan{}).
		Owns(&batchv1.Job{}). // Job status changes wake the owning ImageScan
		// One reconcile at a time: the cluster-wide "no scan running" check in progress()
		// is only race-free if two reconciles can't both see "0 running" at the same time.
		WithOptions(crcontroller.Options{MaxConcurrentReconciles: 1}).
		Named("imagescan").
		Complete(r)
}
