package v1alpha1

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

func newTestValidator(t *testing.T) *ImageScanValidator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", Labels: map[string]string{"app": "web"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "nginx:1.25"}}},
		},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "good"}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte("{}")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "opaque"}, Type: corev1.SecretTypeOpaque},
	).Build()
	return &ImageScanValidator{Client: c, APIReader: c, Excluded: map[string]bool{}, Namespace: "ops"}
}

func scanWith(mutate func(*securityv1alpha1.ImageScan)) *securityv1alpha1.ImageScan {
	s := &securityv1alpha1.ImageScan{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
	s.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func TestValidateCreate(t *testing.T) {
	v := newTestValidator(t)
	secret := func(name string) func(*securityv1alpha1.ImageScan) {
		return func(s *securityv1alpha1.ImageScan) {
			s.Spec.RegistrySecretRef = &corev1.LocalObjectReference{Name: name}
		}
	}
	cases := []struct {
		name    string
		scan    *securityv1alpha1.ImageScan
		wantErr string // "" = must be accepted
	}{
		{"valid", scanWith(nil), ""},
		{"valid with registry secret", scanWith(secret("good")), ""},
		{"no matching pods", scanWith(func(s *securityv1alpha1.ImageScan) {
			s.Spec.PodSelector.MatchLabels = map[string]string{"app": "wbe"}
		}), "matches no pods"},
		{"invalid selector operator", scanWith(func(s *securityv1alpha1.ImageScan) {
			s.Spec.PodSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: "Inn", Values: []string{"web"}}}}
		}), "spec.podSelector"},
		{"missing secret", scanWith(secret("missing")), "Not found"},
		{"wrong secret type", scanWith(secret("opaque")), "kubernetes.io/dockerconfigjson"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warnings, err := v.ValidateCreate(context.Background(), c.scan)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got %v", err)
				}
				if !strings.Contains(strings.Join(warnings, " "), "nginx:1.25") {
					t.Errorf("expected a warning listing nginx:1.25, got %v", warnings)
				}
				return
			}
			if err == nil || !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("want an Invalid error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}
