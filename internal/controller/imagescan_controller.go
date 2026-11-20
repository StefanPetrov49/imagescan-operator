/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	"github.com/StefanPetrov49/imagescan-operator/internal/targeting"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// ImageScanReconciler reconciles a ImageScan object
type ImageScanReconciler struct {
	client.Client
	APIReader       client.Reader // reads straight from the API server (no cache lag)
	Scheme          *runtime.Scheme
	SummarizerImage string          // image containing /summarize
	Excluded        map[string]bool // namespaces never scanned (from --excluded-namespaces)
	Namespace       string
	ResultsPVC      string
	TrivyImage      string
}

// +kubebuilder:rbac:groups=security.stefanpetrov.dev,resources=imagescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stefanpetrov.dev,resources=imagescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.stefanpetrov.dev,resources=imagescans/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Load the ImageScan. If it was deleted, there's nothing to do.
	var scan securityv1alpha1.ImageScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Finished: make sure no Jobs are left behind, then stop.
	if isTerminal(scan.Status.Phase) {
		return ctrl.Result{}, r.deleteFinishedJobs(ctx, &scan)
	}

	// 3. First run: resolve images once and record them.
	if scan.Status.Phase == "" {
		log.Info("resolving target images", "imagescan", scan.Name)
		return r.initialize(ctx, &scan)
	}

	// 4. Running: drive scans forward.
	return r.progress(ctx, &scan)
}

// initialize resolves target images and records one Pending scan per image.
func (r *ImageScanReconciler) initialize(ctx context.Context, scan *securityv1alpha1.ImageScan) (ctrl.Result, error) {
	images, err := targeting.FindTargetImages(ctx, r.Client, scan.Spec, r.Excluded)
	if err != nil {
		// Probably temporary (API hiccup): return the error so controller-runtime retries.
		return ctrl.Result{}, err
	}

	if len(images) == 0 {
		// Permanent: nothing to scan. Record it and stop.
		scan.Status.Phase = securityv1alpha1.PhaseFailed
		scan.Status.Message = "no pods match the given selectors"
		return ctrl.Result{}, r.Status().Update(ctx, scan)
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
	return ctrl.Result{}, r.Status().Update(ctx, scan)
}

func (r *ImageScanReconciler) progress(ctx context.Context, scan *securityv1alpha1.ImageScan) (ctrl.Result, error) {
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
			if err := r.createJob(ctx, scan, *res); err != nil { // cache lag: re-create is safe
				return ctrl.Result{}, err
			}
		case err != nil:
			return ctrl.Result{}, err
		default:
			res.Phase, res.Message = jobOutcome(&job)
			res.StartTime = job.Status.StartTime
			if isTerminal(res.Phase) {
				res.CompletionTime = finishTime(&job)
				if res.StartTime != nil && res.CompletionTime != nil {
					logf.FromContext(ctx).Info("scan finished", "image", res.Image, "phase", res.Phase,
						"duration", res.CompletionTime.Sub(res.StartTime.Time).Round(time.Second).String())
				}
			}
		}
	}

	// Step 2: start the next Pending scan, but only if nothing is running anywhere.
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

	// Step 3: record, then clean up.
	scan.Status.Phase = overallPhase(scan.Status.Scans)
	if err := r.Status().Update(ctx, scan); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil // stale copy, just retry
		}
		return ctrl.Result{}, err
	}
	if err := r.deleteFinishedJobs(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}

	// Step 4: something still waiting for its turn? Check back later.
	if hasPending(scan.Status.Scans) {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
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
		err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
		if client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

const maxRunningScans = 1 // shared Trivy cache: one scan at a time, cluster-wide

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

// runningScanJobs counts unfinished Trivy Jobs across ALL ImageScans, read live from the API server.
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

func hasPending(scans []securityv1alpha1.ImageScanResult) bool {
	for _, s := range scans {
		if s.Phase == securityv1alpha1.PhasePending {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ImageScan{}).
		Owns(&batchv1.Job{}). // Job changes → reconcile the owning ImageScan
		Named("imagescan").
		Complete(r)
}
