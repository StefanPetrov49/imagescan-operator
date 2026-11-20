package targeting

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// ParseExcluded turns "kube-system,local-path-storage" into a lookup set.
func ParseExcluded(csv string) map[string]bool {
	excluded := map[string]bool{}
	for ns := range strings.SplitSeq(csv, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			excluded[ns] = true
		}
	}
	return excluded
}

// FindTargetImages returns the sorted, unique images of all pods matched by spec,
// skipping excluded namespaces. Used by both the controller and the webhook so
// they always agree on what is targeted. It only reads, so it takes a client.Reader.
func FindTargetImages(ctx context.Context, c client.Reader,
	spec securityv1alpha1.ImageScanSpec, excluded map[string]bool) ([]string, error) {

	nsSel, err := metav1.LabelSelectorAsSelector(&spec.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	podSel, err := metav1.LabelSelectorAsSelector(&spec.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid podSelector: %w", err)
	}

	// 1. Namespaces matching the namespace selector (their labels live on the Namespace).
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList, client.MatchingLabelsSelector{Selector: nsSel}); err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	// 2. Pods in each of them, collecting images into a set.
	seen := map[string]struct{}{}
	add := func(containers []corev1.Container) {
		for _, ctr := range containers {
			if plausibleImage(ctr.Image) {
				seen[ctr.Image] = struct{}{}
			}
		}
	}
	for _, ns := range nsList.Items {
		if excluded[ns.Name] {
			continue
		}
		var pods corev1.PodList
		if err := c.List(ctx, &pods,
			client.InNamespace(ns.Name),
			client.MatchingLabelsSelector{Selector: podSel}); err != nil {
			return nil, fmt.Errorf("listing pods in %s: %w", ns.Name, err)
		}
		for _, pod := range pods.Items {
			add(pod.Spec.InitContainers) // init containers and native sidecars run too
			add(pod.Spec.Containers)
		}
	}

	// 3. Set -> sorted slice (Go randomizes map order; a stable order keeps the status stable).
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	slices.Sort(images)
	return images, nil
}

// plausibleImage filters out strings that can't be an image reference. Kubernetes doesn't
// validate the format of a Pod's image, and the value becomes a command-line argument of
// Trivy, so something like "--input=/etc/passwd" must never get through.
func plausibleImage(img string) bool {
	return img != "" && !strings.HasPrefix(img, "-") && !strings.ContainsAny(img, " \t\r\n")
}
