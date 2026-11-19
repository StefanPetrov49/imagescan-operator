package targeting

import (
	"context"
	"fmt"
	"sort"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// findTargetImages returns the sorted, unique images of all pods matched by spec,
// skipping excluded namespaces.
func findTargetImages(ctx context.Context, c client.Client,
	spec securityv1alpha1.ImageScanSpec, excluded map[string]bool) ([]string, error) {

	nsSel, err := metav1.LabelSelectorAsSelector(&spec.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	podSel, err := metav1.LabelSelectorAsSelector(&spec.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid podSelector: %w", err)
	}

	// 1. Namespaces matching the namespace selector
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList, client.MatchingLabelsSelector{Selector: nsSel}); err != nil {
		return nil, err
	}

	// 2. Pods in each of them, collecting images into a set
	seen := map[string]struct{}{}
	for _, ns := range nsList.Items {
		if excluded[ns.Name] {
			continue
		}
		var pods corev1.PodList
		if err := c.List(ctx, &pods,
			client.InNamespace(ns.Name),
			client.MatchingLabelsSelector{Selector: podSel}); err != nil {
			return nil, err
		}
		for _, pod := range pods.Items {
			for _, ctr := range pod.Spec.Containers {
				seen[ctr.Image] = struct{}{}
			}
			for _, ctr := range pod.Spec.InitContainers {
				seen[ctr.Image] = struct{}{}
			}
		}
	}

	// 3. Map → sorted slice
	images := make([]string, 0, len(seen))
	for img := range seen {
		images = append(images, img)
	}
	sort.Strings(images)
	return images, nil
}
