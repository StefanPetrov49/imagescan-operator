package controller

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
	"github.com/StefanPetrov49/imagescan-operator/internal/results"
)

// Labels and annotations on scan Jobs and their Pods.
const (
	// labelImageScanUID uses the UID, not the name: label values are limited to 63
	// characters, while object names can be up to 253.
	labelImageScanUID = "security.stefanpetrov.dev/imagescan-uid"
	labelScanID       = "security.stefanpetrov.dev/scan-id"
	// Image references contain ':' and '/', which label values can't: annotations instead.
	annotationImage     = "security.stefanpetrov.dev/image"
	annotationImageScan = "security.stefanpetrov.dev/imagescan"
)

// Names and paths inside the scan Pod.
const (
	trivyContainerName = "trivy"
	resultsVolume      = "results"
	tmpVolume          = "tmp"
	dockerConfVolume   = "docker-config"
	resultsMount       = "/data"
	trivyCacheDir      = resultsMount + "/trivy-cache" // shared by all scans, see maxRunningScans
	dockerConfDir      = "/docker-config"
)

// nonRootUID is the same non-root user as in our distroless image.
const nonRootUID int64 = 65532

// Time limits. The Job deadline must be LONGER than Trivy's own timeout, so Trivy can
// fail with its own error message instead of being killed without one.
const (
	trivyTimeout                = "30m"
	jobDeadlineSeconds    int64 = 40 * 60
	jobBackoffLimit       int32 = 1       // one retry for transient errors, e.g. a network blip
	jobTTLSecondsFinished int32 = 60 * 60 // safety net only: the operator deletes finished Jobs itself
)

// jobName is the Job name for a scan ID. Stable, so creation is idempotent.
func jobName(id string) string { return "trivy-" + id }

// buildTrivyJob returns a Job that scans one image (init container: trivy) and then
// writes a small summary next to the report (container: summarize).
func (r *ImageScanReconciler) buildTrivyJob(scan *securityv1alpha1.ImageScan,
	res securityv1alpha1.ImageScanResult) (*batchv1.Job, error) {

	args := []string{
		"image",
		"--format", "json",
		"--output", resultsMount + "/" + results.ReportFile(res.ID),
		"--cache-dir", trivyCacheDir,
		"--scanners", "vuln",
		"--timeout", trivyTimeout,
		"--skip-version-check",
	}
	if scan.Spec.MinSeverity != "" {
		args = append(args, "--severity", severitiesFrom(scan.Spec.MinSeverity))
	}
	// "--" ends the flags. The image reference comes from a Pod spec, whose format
	// Kubernetes doesn't validate, so it must never be parsed as a Trivy flag.
	args = append(args, "--", res.Image)

	volumes := []corev1.Volume{
		{Name: resultsVolume, VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.ResultsPVC},
		}},
		{Name: tmpVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			SizeLimit: new(resource.MustParse("2Gi")), // a scan can't fill the node's disk
		}}},
	}
	trivyMounts := []corev1.VolumeMount{
		{Name: resultsVolume, MountPath: resultsMount},
		{Name: tmpVolume, MountPath: "/tmp"},
	}
	var env []corev1.EnvVar

	// Private registry: mount the dockerconfigjson Secret as config.json and point Trivy at it.
	if ref := scan.Spec.RegistrySecretRef; ref != nil {
		volumes = append(volumes, corev1.Volume{Name: dockerConfVolume, VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: ref.Name,
				Items:      []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: "config.json"}},
			},
		}})
		trivyMounts = append(trivyMounts,
			corev1.VolumeMount{Name: dockerConfVolume, MountPath: dockerConfDir, ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerConfDir})
	}

	hardened := &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		ReadOnlyRootFilesystem:   new(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}

	trivy := corev1.Container{
		Name:            trivyContainerName,
		Image:           r.TrivyImage,
		Args:            args,
		Env:             env,
		VolumeMounts:    trivyMounts,
		SecurityContext: hardened,
		// On failure, Kubernetes keeps the end of Trivy's log as the termination message,
		// which the controller copies into the status (see scannerError).
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
		},
	}
	summarize := corev1.Container{
		Name:    "summarize",
		Image:   r.SummarizerImage,
		Command: []string{"/summarize"},
		Args: []string{
			"--results-dir", resultsMount,
			"--id", res.ID,
			"--imagescan", scan.Name,
			"--image", res.Image,
			"--min-severity", string(scan.Spec.MinSeverity),
		},
		VolumeMounts:    []corev1.VolumeMount{{Name: resultsVolume, MountPath: resultsMount}},
		SecurityContext: hardened,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
		},
	}

	labels := map[string]string{
		labelImageScanUID: string(scan.UID),
		labelScanID:       res.ID,
	}
	annotations := map[string]string{
		annotationImage:     res.Image,
		annotationImageScan: scan.Name,
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName(res.ID),
			Namespace:   r.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            new(jobBackoffLimit),
			ActiveDeadlineSeconds:   new(jobDeadlineSeconds),
			TTLSecondsAfterFinished: new(jobTTLSecondsFinished),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					// Trivy is a third-party image: it gets no Kubernetes API token.
					AutomountServiceAccountToken: new(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   new(true),
						RunAsUser:      new(nonRootUID),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: []corev1.Container{trivy},     // 1st: scan
					Containers:     []corev1.Container{summarize}, // 2nd: summarize
					Volumes:        volumes,
				},
			},
		},
	}

	// The ImageScan owns the Job: Job changes wake our controller, and deleting the
	// ImageScan garbage-collects its Jobs.
	if err := controllerutil.SetControllerReference(scan, job, r.Scheme); err != nil {
		return nil, err
	}
	return job, nil
}
