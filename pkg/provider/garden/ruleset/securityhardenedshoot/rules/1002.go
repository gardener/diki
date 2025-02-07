// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
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
	Name                    string   `json:"name" yaml:"name"`
	ExpectedClassifications []string `json:"expectedClassifications" yaml:"expectedClassifications"`
}

func (o Options1002) Validate() field.ErrorList {
	var (
		allErrs                field.ErrorList
		rootPath               = field.NewPath("machineImages")
		versionClassifications = []string{string(core.ClassificationPreview), string(core.ClassificationSupported), string(core.ClassificationDeprecated)}
	)

	for _, machineImage := range o.MachineImages {
		for _, c := range machineImage.ExpectedClassifications {
			if !slices.Contains(versionClassifications, c) {
				allErrs = append(allErrs, field.NotSupported(rootPath.Child("expectedClassifications"), c, versionClassifications))
			}
		}
	}
	return allErrs
}

func (r *Rule1002) ID() string {
	return "1002"
}

func (r *Rule1002) Name() string {
	return "Shoot clusters should use supported versions for their Worker's images."
}

func (r *Rule1002) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule1002) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
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

	if kind == gardencorev1beta1constants.CloudProfileReferenceKindCloudProfile {
		cloudProfile = &gardencorev1beta1.CloudProfile{ObjectMeta: v1.ObjectMeta{Name: cloudProfileName}}
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(cloudProfile), cloudProfile); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", cloudProfileName, "kind", "CloudProfile"))), nil
		}
	} else if kind == gardencorev1beta1constants.CloudProfileReferenceKindNamespacedCloudProfile {
		namespacedCloudProfile = &gardencorev1beta1.NamespacedCloudProfile{ObjectMeta: v1.ObjectMeta{Name: cloudProfileName, Namespace: r.ShootNamespace}}
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(namespacedCloudProfile), namespacedCloudProfile); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", cloudProfileName, "namespace", r.ShootNamespace, "kind", "NamespacedCloudProfile"))), nil
		}
	} else {
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("cloudProfile kind %s not recognised", kind), rule.NewTarget())), nil
	}

	for _, worker := range shoot.Spec.Provider.Workers {
		target := rule.NewTarget("worker", worker.Name, "image", worker.Machine.Image.Name, "version", *worker.Machine.Image.Version)
		checkResults = append(checkResults, r.checkImageVersion(
			worker.Machine.Image.Name,
			*worker.Machine.Image.Version,
			cloudProfile,
			namespacedCloudProfile,
			target,
		))
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule1002) checkImageVersion(
	imageName, imageVersion string,
	cloudProfile *gardencorev1beta1.CloudProfile,
	namespacedCloudProfile *gardencorev1beta1.NamespacedCloudProfile,
	target rule.Target,
) rule.CheckResult {
	if cloudProfile != nil {
		return r.checkCloudProfile(imageName, imageVersion, *cloudProfile, target)
	} else {
		return r.checkNamespacedCloudProfile(imageName, imageVersion, *namespacedCloudProfile, target)
	}
}

func (r *Rule1002) checkNamespacedCloudProfile(
	imageName, imageVersion string,
	namespacedCloudProfile gardencorev1beta1.NamespacedCloudProfile,
	target rule.Target,
) rule.CheckResult {
	result, found := r.checkMachineImages(imageName, imageVersion, namespacedCloudProfile.Spec.MachineImages, target)
	if found {
		return result
	}

	result, found = r.checkMachineImages(imageName, imageVersion, namespacedCloudProfile.Status.CloudProfileSpec.MachineImages, target)
	if found {
		return result
	}
	return rule.ErroredCheckResult("image version not found in namespacedCloudProfile", target)
}

func (r *Rule1002) checkCloudProfile(
	imageName, imageVersion string,
	cloudProfile gardencorev1beta1.CloudProfile,
	target rule.Target,
) rule.CheckResult {
	result, found := r.checkMachineImages(imageName, imageVersion, cloudProfile.Spec.MachineImages, target)
	if found {
		return result
	}

	return rule.ErroredCheckResult("image version not found in cloudProfile", target)
}

func (r *Rule1002) checkMachineImages(imageName, imageVersion string, machineImages []gardencorev1beta1.MachineImage, target rule.Target) (rule.CheckResult, bool) {
	for _, machineImage := range machineImages {
		if machineImage.Name == imageName {
			for _, version := range machineImage.Versions {
				if version.Version == imageVersion {
					if version.Classification == nil {
						return rule.FailedCheckResult("Worker group uses image with unclassified image.", target), true
					} else if slices.Contains(r.acceptedClassifications(imageName), string(*version.Classification)) {
						return rule.PassedCheckResult("Worker group has accepted image.", target.With("classification", string(*version.Classification))), true
					} else {
						return rule.FailedCheckResult("Worker group has not accepted image.", target.With("classification", string(*version.Classification))), true
					}
				}
			}
		}
	}
	return rule.CheckResult{}, false
}

func (r *Rule1002) acceptedClassifications(name string) []string {
	if r.Options != nil {
		for _, machineImage := range r.Options.MachineImages {
			if machineImage.Name == name {

				return machineImage.ExpectedClassifications
			}
		}
	}

	return []string{string(core.ClassificationSupported)}
}
