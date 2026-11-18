package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Severity is a Trivy vulnerability severity level.
// +kubebuilder:validation:Enum=UNKNOWN;LOW;MEDIUM;HIGH;CRITICAL
type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ScanPhase is the state of a scan. PartiallyFailed is only used for the overall phase.
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;PartiallyFailed;Failed
type ScanPhase string

const (
	PhasePending         ScanPhase = "Pending"
	PhaseRunning         ScanPhase = "Running"
	PhaseSucceeded       ScanPhase = "Succeeded"
	PhasePartiallyFailed ScanPhase = "PartiallyFailed"
	PhaseFailed          ScanPhase = "Failed"
)

// ImageScanSpec defines which pods' images should be scanned and how.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type ImageScanSpec struct {
	// NamespaceSelector selects namespaces. Empty/omitted = all non-excluded namespaces.
	// +optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector selects pods within those namespaces. Empty/omitted = all pods.
	// +optional
	PodSelector metav1.LabelSelector `json:"podSelector,omitempty"`

	// MinSeverity is the lowest severity included in results. Omitted = all severities.
	// +optional
	MinSeverity Severity `json:"minSeverity,omitempty"`

	// RegistrySecretRef names a dockerconfigjson Secret in the operator's
	// namespace, used to pull images from private registries.
	// +optional
	RegistrySecretRef *corev1.LocalObjectReference `json:"registrySecretRef,omitempty"`
}

// ImageScanStatus is written by the operator.
type ImageScanStatus struct {
	// Phase is the overall state of the ImageScan.
	// +optional
	Phase ScanPhase `json:"phase,omitempty"`

	// Message explains an overall failure (e.g. no pods found, secret missing).
	// +optional
	Message string `json:"message,omitempty"`

	// Scans has one entry per unique image.
	// +optional
	Scans []ImageScanResult `json:"scans,omitempty"`
}

// ImageScanResult is the state of the scan of one unique image.
type ImageScanResult struct {
	// ID identifies this scan; use it with GET /scans/{id}.
	ID string `json:"id"`

	// Image is the scanned image reference, e.g. nginx:1.25.
	Image string `json:"image"`

	// Phase of this image's scan.
	Phase ScanPhase `json:"phase"`

	// Message explains a failure.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageScan requests a Trivy scan of the images used by selected pods.
type ImageScan struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines which pods' images should be scanned
	// +required
	Spec ImageScanSpec `json:"spec"`

	// status is written by the operator
	// +optional
	Status ImageScanStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageScanList contains a list of ImageScan.
type ImageScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ImageScan{}, &ImageScanList{})
		return nil
	})
}
