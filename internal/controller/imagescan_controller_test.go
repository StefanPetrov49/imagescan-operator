package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// These tests run Reconcile against a real API server (envtest). There is no Job
// controller in envtest, so Jobs are created but never run: the tests check what the
// operator writes, not what Trivy does.
var _ = Describe("ImageScan Controller", func() {
	const jobNamespace = "default" // envtest has no operator namespace

	newReconciler := func() *ImageScanReconciler {
		return &ImageScanReconciler{
			Client:          k8sClient,
			APIReader:       k8sClient,
			Scheme:          k8sClient.Scheme(),
			Namespace:       jobNamespace,
			Excluded:        map[string]bool{},
			ResultsPVC:      "results",
			TrivyImage:      "aquasec/trivy:test",
			SummarizerImage: "imagescan-operator:test",
		}
	}
	reconcileOnce := func(name string) {
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())
	}
	getScan := func(name string) *securityv1alpha1.ImageScan {
		scan := &securityv1alpha1.ImageScan{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, scan)).To(Succeed())
		return scan
	}
	createScan := func(name, app string) {
		scan := &securityv1alpha1.ImageScan{ObjectMeta: metav1.ObjectMeta{Name: name}}
		scan.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}
		Expect(k8sClient.Create(ctx, scan)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, scan)
	}

	It("fails permanently when no pods match", func() {
		createScan("no-match", "does-not-exist")

		reconcileOnce("no-match")

		scan := getScan("no-match")
		Expect(scan.Status.Phase).To(Equal(securityv1alpha1.PhaseFailed))
		Expect(scan.Status.Message).To(ContainSubstring("no pods match"))
	})

	It("resolves images once, then creates one hardened Job per image", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "web", Namespace: "default", Labels: map[string]string{"app": "ctrl-test"},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "nginx:1.25"}}},
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, pod)
		createScan("web-scan", "ctrl-test")

		By("first reconcile: images resolved, one Pending scan with a deterministic ID")
		reconcileOnce("web-scan")
		scan := getScan("web-scan")
		Expect(scan.Status.Phase).To(Equal(securityv1alpha1.PhaseRunning))
		Expect(scan.Status.Scans).To(HaveLen(1))
		Expect(scan.Status.Scans[0].Image).To(Equal("nginx:1.25"))
		Expect(scan.Status.Scans[0].Phase).To(Equal(securityv1alpha1.PhasePending))
		id := scan.Status.Scans[0].ID
		Expect(id).To(Equal(scanID(scan.UID, "nginx:1.25")))

		By("second reconcile: the Job is created and the scan is Running")
		reconcileOnce("web-scan")
		Expect(getScan("web-scan").Status.Scans[0].Phase).To(Equal(securityv1alpha1.PhaseRunning))

		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: jobNamespace, Name: jobName(id)}, job)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, job)

		Expect(job.Labels).To(HaveKeyWithValue(labelImageScanUID, string(scan.UID)))
		Expect(job.OwnerReferences).To(HaveLen(1))
		Expect(job.OwnerReferences[0].UID).To(Equal(scan.UID))
		podSpec := job.Spec.Template.Spec
		Expect(podSpec.AutomountServiceAccountToken).To(HaveValue(BeFalse()))
		args := podSpec.InitContainers[0].Args
		Expect(args[len(args)-2:]).To(Equal([]string{"--", "nginx:1.25"}))

		By("reconciling again creates no second Job (idempotent)")
		reconcileOnce("web-scan")
		var jobs batchv1.JobList
		Expect(k8sClient.List(ctx, &jobs, client.InNamespace(jobNamespace),
			client.MatchingLabels{labelScanID: id})).To(Succeed())
		Expect(jobs.Items).To(HaveLen(1))
	})
})
