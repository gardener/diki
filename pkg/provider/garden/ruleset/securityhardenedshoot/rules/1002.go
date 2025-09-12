// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule1002{}
	_ rule.Severity = &Rule1002{}
	_ option.Option = &Options1002{}
)

type Rule1002 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
	Options        *Options1002
}

type Options1002 struct {
	MachineImages []MachineImage `json:"machineImages" yaml:"machineImages"`
}

type MachineImage struct {
	Name                   string                                    `json:"name" yaml:"name"`
	AllowedClassifications []gardencorev1beta1.VersionClassification `json:"allowedClassifications" yaml:"allowedClassifications"`
}

func (o Options1002) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs                field.ErrorList
		machineImagesPath      = fldPath.Child("machineImages")
		versionClassifications = []gardencorev1beta1.VersionClassification{
			gardencorev1beta1.ClassificationPreview,
			gardencorev1beta1.ClassificationSupported,
			gardencorev1beta1.ClassificationDeprecated,
		}
	)

	for mIdx, machineImage := range o.MachineImages {
		if len(machineImage.Name) == 0 {
			allErrs = append(allErrs, field.Required(machineImagesPath.Index(mIdx).Child("name"), "must not be empty"))
		}

		for cIdx, c := range machineImage.AllowedClassifications {
			if !slices.Contains(versionClassifications, c) {
				allErrs = append(allErrs, field.NotSupported(machineImagesPath.Index(mIdx).Child("allowedClassifications").Index(cIdx), c, versionClassifications))
			}
		}
	}
	return allErrs
}

func (r *Rule1002) ID() string {
	return "1002"
}

func (r *Rule1002) Name() string {
	return "Shoot clusters should use supported versions for their Workers' images."
}

func (r *Rule1002) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule1002) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	var (
		checkResults           []rule.CheckResult
		cloudProfileName       string
		kind                   string
		cloudProfile           *gardencorev1beta1.CloudProfile
		namespacedCloudProfile *gardencorev1beta1.NamespacedCloudProfile
	)

	if shoot.Spec.CloudProfile != nil {
		cloudProfileName = shoot.Spec.CloudProfile.Name
		kind = shoot.Spec.CloudProfile.Kind
	} else {
		cloudProfileName = *shoot.Spec.CloudProfileName
		kind = gardencorev1beta1constants.CloudProfileReferenceKindCloudProfile
	}

	switch kind {
	case gardencorev1beta1constants.CloudProfileReferenceKindCloudProfile:
		cloudProfile = &gardencorev1beta1.CloudProfile{ObjectMeta: v1.ObjectMeta{Name: cloudProfileName}}
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(cloudProfile), cloudProfile); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "CloudProfile"}, cloudProfile.ObjectMeta))), nil
		}
	case gardencorev1beta1constants.CloudProfileReferenceKindNamespacedCloudProfile:
		namespacedCloudProfile = &gardencorev1beta1.NamespacedCloudProfile{ObjectMeta: v1.ObjectMeta{Name: cloudProfileName, Namespace: r.ShootNamespace}}
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(namespacedCloudProfile), namespacedCloudProfile); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "NamespacedCloudProfile"}, namespacedCloudProfile.ObjectMeta))), nil
		}
	default:
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("cloudProfile kind %s not recognised", kind), rule.NewTarget())), nil
	}

	for _, worker := range shoot.Spec.Provider.Workers {
		target := rule.NewTarget("worker", worker.Name, "image", worker.Machine.Image.Name, "version", *worker.Machine.Image.Version)
		if kind == gardencorev1beta1constants.CloudProfileReferenceKindCloudProfile {
			checkResult, found := r.checkMachineImages(worker.Machine.Image.Name, *worker.Machine.Image.Version, cloudProfile.Spec.MachineImages, target)
			if found {
				checkResults = append(checkResults, checkResult)
			} else {
				checkResults = append(checkResults, rule.ErroredCheckResult("image version not found in cloudProfile", target))
			}
		} else {
			checkResult, found := r.checkMachineImages(worker.Machine.Image.Name, *worker.Machine.Image.Version, namespacedCloudProfile.Spec.MachineImages, target)
			if found {
				checkResults = append(checkResults, checkResult)
				continue
			}

			checkResult, found = r.checkMachineImages(worker.Machine.Image.Name, *worker.Machine.Image.Version, namespacedCloudProfile.Status.CloudProfileSpec.MachineImages, target)
			if found {
				checkResults = append(checkResults, checkResult)
			} else {
				checkResults = append(checkResults, rule.ErroredCheckResult("image version not found in namespacedCloudProfile", target))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule1002) checkMachineImages(imageName, imageVersion string, machineImages []gardencorev1beta1.MachineImage, target rule.Target) (rule.CheckResult, bool) {
	for _, machineImage := range machineImages {
		if machineImage.Name == imageName {
			for _, version := range machineImage.Versions {
				if version.Version == imageVersion {
					switch {
					case version.Classification == nil:
						return rule.FailedCheckResult("Worker group uses image with unclassified image.", target), true
					case slices.Contains(r.acceptedClassifications(imageName), *version.Classification):
						return rule.PassedCheckResult("Worker group uses allowed classification of machine image.", target.With("classification", string(*version.Classification))), true
					default:
						return rule.FailedCheckResult("Worker group uses not allowed classification of machine image.", target.With("classification", string(*version.Classification))), true
					}
				}
			}
		}
	}
	return rule.CheckResult{}, false
}

func (r *Rule1002) acceptedClassifications(name string) []gardencorev1beta1.VersionClassification {
	if r.Options != nil {
		for _, machineImage := range r.Options.MachineImages {
			if machineImage.Name == name {
				return machineImage.AllowedClassifications
			}
		}
	}

	return []gardencorev1beta1.VersionClassification{gardencorev1beta1.ClassificationSupported}
}
