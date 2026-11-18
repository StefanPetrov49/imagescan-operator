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

package v1alpha1

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/StefanPetrov49/imagescan-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var imagescanlog = logf.Log.WithName("imagescan-resource")

// SetupImageScanWebhookWithManager registers the webhook for ImageScan in the manager.
func SetupImageScanWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &securityv1alpha1.ImageScan{}).
		WithValidator(&ImageScanValidator{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-security-stefanpetrov-dev-v1alpha1-imagescan,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.stefanpetrov.dev,resources=imagescans,verbs=create;update,versions=v1alpha1,name=vimagescan-v1alpha1.kb.io,admissionReviewVersions=v1

// ImageScanValidator struct is responsible for validating the ImageScan resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ImageScanValidator struct {
	// TODO(user): Add more fields as needed for validation
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type ImageScan.
func (v *ImageScanValidator) ValidateCreate(_ context.Context, obj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon creation", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type ImageScan.
func (v *ImageScanValidator) ValidateUpdate(_ context.Context, oldObj, newObj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon update", "name", newObj.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type ImageScan.
func (v *ImageScanValidator) ValidateDelete(_ context.Context, obj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
