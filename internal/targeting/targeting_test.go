package targeting

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

func TestParseExcluded(t *testing.T) {
	got := ParseExcluded(" kube-system, local-path-storage,,")
	want := map[string]bool{"kube-system": true, "local-path-storage": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if len(ParseExcluded("")) != 0 {
		t.Error("empty flag must exclude nothing")
	}
}

func namespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func pod(ns, name string, labels map[string]string, initImages []string, images ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels}}
	for i, img := range initImages {
		p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: "init" + string(rune('a'+i)), Image: img})
	}
	for i, img := range images {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "c" + string(rune('a'+i)), Image: img})
	}
	return p
}

func testClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	prod := map[string]string{"env": "production"}
	web := map[string]string{"app": "web"}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		namespace("prod", prod),
		namespace("dev", map[string]string{"env": "dev"}),
		namespace("kube-system", prod), // matches the label, but is excluded
		pod("prod", "web-1", web, []string{"busybox:1.36"}, "nginx:1.25", "envoy:1.30"),
		pod("prod", "web-2", web, nil, "nginx:1.25"),                          // duplicate image
		pod("prod", "db", map[string]string{"app": "db"}, nil, "postgres:16"), // wrong pod label
		pod("dev", "web-dev", web, nil, "nginx:dev"),                          // wrong namespace label
		pod("kube-system", "web-sys", web, nil, "nginx:sys"),                  // excluded namespace
		pod("prod", "evil", web, nil, "--input=/etc/passwd"),                  // not an image: flag injection
	).Build()
}

func TestFindTargetImages(t *testing.T) {
	c := testClient(t)
	excluded := map[string]bool{"kube-system": true}
	ctx := context.Background()

	t.Run("selectors, dedup, init containers, exclusion, sorted", func(t *testing.T) {
		spec := securityv1alpha1.ImageScanSpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "production"}},
			PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		}
		got, err := FindTargetImages(ctx, c, spec, excluded)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"busybox:1.36", "envoy:1.30", "nginx:1.25"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("empty selectors mean every non-excluded namespace and pod", func(t *testing.T) {
		got, err := FindTargetImages(ctx, c, securityv1alpha1.ImageScanSpec{}, excluded)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"busybox:1.36", "envoy:1.30", "nginx:1.25", "nginx:dev", "postgres:16"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("invalid selector is an error", func(t *testing.T) {
		spec := securityv1alpha1.ImageScanSpec{PodSelector: metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Inn", Values: []string{"web"}}},
		}}
		if _, err := FindTargetImages(ctx, c, spec, excluded); err == nil {
			t.Error("expected an error for operator \"Inn\"")
		}
	})
}
func TestPlausibleImage(t *testing.T) {
	for img, want := range map[string]bool{
		"nginx:1.25":                        true,
		"docker.io/library/nginx:1.25":      true,
		"registry:5000/team/app@sha256:abc": true,
		"":                                  false,
		"--input=/etc/passwd":               false,
		"-v":                                false,
		"nginx 1.25":                        false,
	} {
		if got := plausibleImage(img); got != want {
			t.Errorf("plausibleImage(%q) = %v, want %v", img, got, want)
		}
	}
}
