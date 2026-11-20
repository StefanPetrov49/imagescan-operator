package controller

import (
	"github.com/StefanPetrov49/imagescan-operator/internal/results"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

const (
	labelImageScan = "security.stefanpetrov.dev/imagescan"
	labelScanID    = "security.stefanpetrov.dev/scan-id"
	resultsMount   = "/data"
	dockerConfDir  = "/docker-config"
)

// jobName is the Job name for a scan ID. Stable, so creation is idempotent.
func jobName(id string) string { return "trivy-" + id }

const annotationImage = "security.stefanpetrov.dev/image"

// buildTrivyJob returns a Job that scans one image (init container: trivy)
// and then writes a small summary next to the report (container: summarize).
func (r *ImageScanReconciler) buildTrivyJob(scan *securityv1alpha1.ImageScan,
	res securityv1alpha1.ImageScanResult) (*batchv1.Job, error) {

	args := []string{
		"image",
		"--format", "json",
		"--output", resultsMount + "/" + results.ReportFile(res.ID),
		"--cache-dir", resultsMount + "/trivy-cache",
		"--scanners", "vuln",
		"--timeout", "30m",
		"--skip-version-check",
	}
	if scan.Spec.MinSeverity != "" {
		args = append(args, "--severity", severitiesFrom(scan.Spec.MinSeverity))
	}
	args = append(args, res.Image)

	volumes := []corev1.Volume{
		{Name: "results", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.ResultsPVC},
		}},
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	trivyMounts := []corev1.VolumeMount{
		{Name: "results", MountPath: resultsMount},
		{Name: "tmp", MountPath: "/tmp"},
	}
	var env []corev1.EnvVar

	if ref := scan.Spec.RegistrySecretRef; ref != nil {
		volumes = append(volumes, corev1.Volume{Name: "docker-config", VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: ref.Name,
				Items:      []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: "config.json"}},
			},
		}})
		trivyMounts = append(trivyMounts, corev1.VolumeMount{Name: "docker-config", MountPath: dockerConfDir, ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerConfDir})
	}

	hardened := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}

	trivy := corev1.Container{
		Name:            "trivy",
		Image:           r.TrivyImage,
		Args:            args,
		Env:             env,
		VolumeMounts:    trivyMounts,
		SecurityContext: hardened,
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
		VolumeMounts:    []corev1.VolumeMount{{Name: "results", MountPath: resultsMount}},
		SecurityContext: hardened,
	}

	labels := map[string]string{
		labelImageScan: scan.Name,
		labelScanID:    res.ID,
	}
	annotations := map[string]string{annotationImage: res.Image}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName(res.ID),
			Namespace:   r.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          ptr.To[int32](1),
			ActiveDeadlineSeconds: ptr.To[int64](2400),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   ptr.To(true),
						RunAsUser:      ptr.To[int64](65532),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: []corev1.Container{trivy},     // 1st: scan
					Containers:     []corev1.Container{summarize}, // 2nd: summarize
					Volumes:        volumes,
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(scan, job, r.Scheme); err != nil {
		return nil, err
	}
	return job, nil
}
