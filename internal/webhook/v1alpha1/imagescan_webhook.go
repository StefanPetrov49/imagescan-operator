package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
	"github.com/StefanPetrov49/imagescan-operator/internal/targeting"
)

// SetupImageScanWebhookWithManager registers the validating webhook for ImageScan.
func SetupImageScanWebhookWithManager(mgr ctrl.Manager, excluded map[string]bool, namespace string) error {
	return ctrl.NewWebhookManagedBy(mgr, &securityv1alpha1.ImageScan{}).
		WithValidator(&ImageScanValidator{
			Client:    mgr.GetClient(),
			APIReader: mgr.GetAPIReader(),
			Excluded:  excluded,
			Namespace: namespace,
		}).
		Complete()
}

// Only CREATE: spec updates are already rejected by the CEL rule, and the checks below
// (pods match, secret exists) describe the moment the scan is requested.
// +kubebuilder:webhook:path=/validate-security-stefanpetrov-dev-v1alpha1-imagescan,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.stefanpetrov.dev,resources=imagescans,verbs=create,versions=v1alpha1,name=vimagescan-v1alpha1.kb.io,admissionReviewVersions=v1

// Reading Secrets: only "get", only in the operator's own namespace (generates a Role, not a ClusterRole).
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get,namespace=system

// ImageScanValidator validates ImageScans when they are created.
// +kubebuilder:object:generate=false
type ImageScanValidator struct {
	// Client reads Pods and Namespaces from the cache (the controller watches them anyway).
	Client client.Reader
	// APIReader reads Secrets directly. A cached read would WATCH all Secrets cluster-wide.
	APIReader client.Reader
	// Excluded is the same exclusion list the controller uses.
	Excluded map[string]bool
	// Namespace is the operator namespace, where registry Secrets must live.
	Namespace string
}

// ValidateCreate rejects ImageScans that would scan nothing or reference a missing Secret.
func (v *ImageScanValidator) ValidateCreate(
	ctx context.Context, scan *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	logf.FromContext(ctx).Info("Validating ImageScan", "name", scan.Name)
	spec := field.NewPath("spec")
	var errs field.ErrorList

	// 1. Selector syntax (e.g. an unknown operator in matchExpressions).
	if _, err := metav1.LabelSelectorAsSelector(&scan.Spec.NamespaceSelector); err != nil {
		errs = append(errs, field.Invalid(spec.Child("namespaceSelector"), scan.Spec.NamespaceSelector, err.Error()))
	}
	if _, err := metav1.LabelSelectorAsSelector(&scan.Spec.PodSelector); err != nil {
		errs = append(errs, field.Invalid(spec.Child("podSelector"), scan.Spec.PodSelector, err.Error()))
	}

	// 2. Registry Secret must exist in the operator namespace and have the right type.
	if ref := scan.Spec.RegistrySecretRef; ref != nil {
		errs = append(errs, v.validateSecret(ctx, spec.Child("registrySecretRef", "name"), ref.Name)...)
	}
	if len(errs) > 0 {
		return nil, invalid(scan, errs)
	}

	// 3. At least one Pod must be targeted (same function the controller uses).
	images, err := targeting.FindTargetImages(ctx, v.Client, scan.Spec, v.Excluded)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if len(images) == 0 {
		return nil, invalid(scan, field.ErrorList{field.Invalid(
			spec.Child("podSelector"), metav1.FormatLabelSelector(&scan.Spec.PodSelector),
			"together with namespaceSelector this matches no pods (excluded namespaces are never scanned)",
		)})
	}

	// Accepted. Warnings are printed by kubectl: useful feedback for the admin.
	var warnings admission.Warnings
	if len(scan.Spec.NamespaceSelector.MatchLabels) == 0 && len(scan.Spec.NamespaceSelector.MatchExpressions) == 0 {
		warnings = append(warnings, "namespaceSelector is empty: all non-excluded namespaces are targeted")
	}
	shown := images
	if len(shown) > 5 {
		shown = shown[:5]
	}
	warnings = append(warnings,
		fmt.Sprintf("%d unique image(s) will be scanned: %s", len(images), strings.Join(shown, ", ")))
	return warnings, nil
}

func (v *ImageScanValidator) validateSecret(ctx context.Context, path *field.Path, name string) field.ErrorList {
	if name == "" {
		return field.ErrorList{field.Required(path, "name of a Secret in namespace "+v.Namespace)}
	}
	var s corev1.Secret
	err := v.APIReader.Get(ctx, types.NamespacedName{Namespace: v.Namespace, Name: name}, &s)
	switch {
	case apierrors.IsNotFound(err):
		return field.ErrorList{field.NotFound(path, v.Namespace+"/"+name)}
	case err != nil:
		return field.ErrorList{field.InternalError(path, err)}
	case s.Type != corev1.SecretTypeDockerConfigJson:
		return field.ErrorList{field.Invalid(path, name, "Secret must be of type "+string(corev1.SecretTypeDockerConfigJson))}
	}
	return nil
}

// invalid builds the standard Kubernetes "is invalid" error, formatted nicely by kubectl.
func invalid(scan *securityv1alpha1.ImageScan, errs field.ErrorList) error {
	gk := securityv1alpha1.SchemeGroupVersion.WithKind("ImageScan").GroupKind()
	return apierrors.NewInvalid(gk, scan.Name, errs)
}

// ValidateUpdate is not registered (verbs=create): spec immutability is enforced by CEL.
func (v *ImageScanValidator) ValidateUpdate(
	_ context.Context, _, _ *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete is not registered: deleting a scan needs no checks.
func (v *ImageScanValidator) ValidateDelete(
	_ context.Context, _ *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	return nil, nil
}
