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
	_ rule.Rule     = &Rule1001{}
	_ rule.Severity = &Rule1001{}
	_ option.Option = &Options1001{}
)

type Rule1001 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
	Options        *Options1001
}

type Options1001 struct {
	AllowedClassifications []gardencorev1beta1.VersionClassification `json:"allowedClassifications" yaml:"allowedClassifications"`
}

func (o Options1001) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs                field.ErrorList
		versionClassifications = []gardencorev1beta1.VersionClassification{
			gardencorev1beta1.ClassificationPreview,
			gardencorev1beta1.ClassificationSupported,
			gardencorev1beta1.ClassificationDeprecated,
		}
	)

	for idx, c := range o.AllowedClassifications {
		if !slices.Contains(versionClassifications, c) {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("allowedClassifications").Index(idx), c, versionClassifications))
		}
	}

	return allErrs
}

func (r *Rule1001) ID() string {
	return "1001"
}

func (r *Rule1001) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule1001) Name() string {
	return "Shoot clusters should use a supported version of Kubernetes."
}

func (r *Rule1001) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	var (
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

	target := rule.NewTarget("version", shoot.Spec.Kubernetes.Version)

	if kind == gardencorev1beta1constants.CloudProfileReferenceKindCloudProfile {
		if checkResult, found := r.checkShootVersion(shoot.Spec.Kubernetes.Version, cloudProfile.Spec.Kubernetes.Versions, target); found {
			return rule.Result(r, checkResult), nil
		}
		return rule.Result(r, rule.ErroredCheckResult("kubernetes version not found in cloudProfile", target)), nil
	}

	if checkResult, found := r.checkShootVersion(shoot.Spec.Kubernetes.Version, namespacedCloudProfile.Spec.Kubernetes.Versions, target); found {
		return rule.Result(r, checkResult), nil
	}
	if checkResult, found := r.checkShootVersion(shoot.Spec.Kubernetes.Version, namespacedCloudProfile.Status.CloudProfileSpec.Kubernetes.Versions, target); found {
		return rule.Result(r, checkResult), nil
	}
	return rule.Result(r, rule.ErroredCheckResult("kubernetes version not found in namespacedCloudProfile", target)), nil
}

func (r *Rule1001) checkShootVersion(shootVersion string, kubernetesVersions []gardencorev1beta1.ExpirableVersion, target rule.Target) (rule.CheckResult, bool) {
	for _, version := range kubernetesVersions {
		if shootVersion == version.Version {
			switch {
			case version.Classification == nil:
				return rule.FailedCheckResult("Shoot uses an unclassified Kubernetes version", target), true
			case slices.Contains(r.acceptedClassifications(), *version.Classification):
				return rule.PassedCheckResult("Shoot uses a Kubernetes version with an allowed classification.", target.With("classification", string(*version.Classification))), true
			default:
				return rule.FailedCheckResult("Shoot uses a Kubernetes version with a forbidden classification.", target.With("classification", string(*version.Classification))), true
			}
		}
	}
	return rule.CheckResult{}, false
}

func (r *Rule1001) acceptedClassifications() []gardencorev1beta1.VersionClassification {
	if r.Options != nil {
		return r.Options.AllowedClassifications
	}
	return []gardencorev1beta1.VersionClassification{gardencorev1beta1.ClassificationSupported}
}
