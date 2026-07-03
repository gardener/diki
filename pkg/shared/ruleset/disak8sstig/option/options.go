// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	"strconv"

	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	intutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

// FileOwnerOptions contains expected user and group owners for files
type FileOwnerOptions struct {
	ExpectedFileOwner ExpectedOwner `json:"expectedFileOwner" yaml:"expectedFileOwner"`
}

var (
	_ option.Option          = &FileOwnerOptions{}
	_ option.MergeableOption = &FileOwnerOptions{}
)

// ExpectedOwner contains expected user and group owners
type ExpectedOwner struct {
	Users  []string `json:"users" yaml:"users"`
	Groups []string `json:"groups" yaml:"groups"`
}

// Merge implements MergeableOption by performing a set union on Users and Groups.
func (o *FileOwnerOptions) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if other == nil {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*FileOwnerOptions](other)
	if err != nil {
		return nil, err
	}

	merged := &FileOwnerOptions{
		ExpectedFileOwner: ExpectedOwner{
			Users:  intutils.MergeStringSlices(o.ExpectedFileOwner.Users, otherOpts.ExpectedFileOwner.Users),
			Groups: intutils.MergeStringSlices(o.ExpectedFileOwner.Groups, otherOpts.ExpectedFileOwner.Groups),
		},
	}

	return merged, nil
}

// Validate validates that option configurations are correctly defined.
func (o FileOwnerOptions) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs               field.ErrorList
		expectedFileOwnerPath = fldPath.Child("expectedFileOwner")
	)
	for uIdx, user := range o.ExpectedFileOwner.Users {
		userID, err := strconv.ParseInt(user, 10, 64)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(expectedFileOwnerPath.Child("users").Index(uIdx), user, err.Error()))
			continue
		}
		for _, msg := range validation.IsValidUserID(userID) {
			allErrs = append(allErrs, field.Invalid(expectedFileOwnerPath.Child("users").Index(uIdx), user, msg))
		}
	}

	for gIdx, group := range o.ExpectedFileOwner.Groups {
		groupID, err := strconv.ParseInt(group, 10, 64)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(expectedFileOwnerPath.Child("groups").Index(gIdx), group, err.Error()))
			continue
		}
		for _, msg := range validation.IsValidGroupID(groupID) {
			allErrs = append(allErrs, field.Invalid(expectedFileOwnerPath.Child("groups").Index(gIdx), group, msg))
		}
	}
	return allErrs
}

// Options242414 contains options for rule 242414
type Options242414 struct {
	AcceptedPods []AcceptedPods242414 `json:"acceptedPods" yaml:"acceptedPods"`
}

var (
	_ option.Option          = &Options242414{}
	_ option.MergeableOption = &Options242414{}
)

// AcceptedPods242414 contains option specifications for accepted pods
type AcceptedPods242414 struct {
	option.AcceptedNamespacedObject
	Ports []int32 `json:"ports" yaml:"ports"`
}

// Merge implements MergeableOption by concatenating AcceptedPods from both options.
func (o *Options242414) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if other == nil {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*Options242414](other)
	if err != nil {
		return nil, err
	}

	merged := &Options242414{
		AcceptedPods: make([]AcceptedPods242414, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Validate validates that option configurations are correctly defined.
func (o Options242414) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs          field.ErrorList
		acceptedPodsPath = fldPath.Child("acceptedPods")
	)
	for idx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(idx))...)
		if len(p.Ports) == 0 {
			allErrs = append(allErrs, field.Required(acceptedPodsPath.Index(idx).Child("ports"), "must not be empty"))
		}
		for pIdx, port := range p.Ports {
			if port < 0 {
				allErrs = append(allErrs, field.Invalid(acceptedPodsPath.Index(idx).Child("ports").Index(pIdx), port, "must not be lower than 0"))
			}
		}
	}
	return allErrs
}

// Options242415 contains options for rule 242415
type Options242415 struct {
	AcceptedPods []AcceptedPods242415 `json:"acceptedPods" yaml:"acceptedPods"`
}

var (
	_ option.Option          = &Options242415{}
	_ option.MergeableOption = &Options242415{}
)

// AcceptedPods242415 contains option specifications for accepted pods
type AcceptedPods242415 struct {
	option.AcceptedNamespacedObject
	EnvironmentVariables []string `json:"environmentVariables" yaml:"environmentVariables"`
}

// Merge implements MergeableOption by concatenating AcceptedPods from both options.
func (o *Options242415) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if other == nil {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*Options242415](other)
	if err != nil {
		return nil, err
	}

	merged := &Options242415{
		AcceptedPods: make([]AcceptedPods242415, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Validate validates that option configurations are correctly defined.
func (o Options242415) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs          field.ErrorList
		acceptedPodsPath = fldPath.Child("acceptedPods")
	)
	for idx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(idx))...)
		if len(p.EnvironmentVariables) == 0 {
			allErrs = append(allErrs, field.Required(acceptedPodsPath.Index(idx).Child("environmentVariables"), "must not be empty"))
		}
		for eIdx, env := range p.EnvironmentVariables {
			for _, msg := range validation.IsEnvVarName(env) {
				allErrs = append(allErrs, field.Invalid(acceptedPodsPath.Index(idx).Child("environmentVariables").Index(eIdx), env, msg))
			}
		}
	}
	return allErrs
}

var (
	_ option.Option          = &Options242442{}
	_ option.MergeableOption = &Options242442{}
)

// Options242442 defines a slice of expected container images for rule 242442.
type Options242442 struct {
	ExpectedVersionedImages []ExpectedVersionedImage `json:"expectedVersionedImages" yaml:"expectedVersionedImages"`
}

// ExpectedVersionedImage contains option specifications for expected to be versioned container images.
type ExpectedVersionedImage struct {
	Name string `json:"name" yaml:"name"`
}

// Merge implements MergeableOption by concatenating ExpectedVersionedImages from both options.
func (o *Options242442) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if other == nil {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*Options242442](other)
	if err != nil {
		return nil, err
	}

	merged := &Options242442{
		ExpectedVersionedImages: make([]ExpectedVersionedImage, 0, len(o.ExpectedVersionedImages)+len(otherOpts.ExpectedVersionedImages)),
	}
	merged.ExpectedVersionedImages = append(merged.ExpectedVersionedImages, o.ExpectedVersionedImages...)
	merged.ExpectedVersionedImages = append(merged.ExpectedVersionedImages, otherOpts.ExpectedVersionedImages...)

	return merged, nil
}

// Validate validates that option configurations are correctly defined.
func (o Options242442) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs                     field.ErrorList
		expectedVersionedImagesPath = fldPath.Child("expectedVersionedImages")
	)

	if len(o.ExpectedVersionedImages) == 0 {
		return field.ErrorList{field.Required(expectedVersionedImagesPath, "must not be empty")}
	}

	for i, a := range o.ExpectedVersionedImages {
		if len(a.Name) == 0 {
			allErrs = append(allErrs, field.Required(expectedVersionedImagesPath.Index(i).Child("name"), "must not be empty"))
		}
	}

	return allErrs
}

// ValidateLabelNames validates that label names a correctly defined
func ValidateLabelNames(labelNames []string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	for _, nodeLabel := range labelNames {
		allErrs = append(allErrs, metav1validation.ValidateLabelName(nodeLabel, fldPath)...)
	}
	return allErrs
}

// KubeProxyOptionsWithoutSelectors contains options for kube-proxy rules
type KubeProxyOptionsWithoutSelectors struct {
	Disabled bool `json:"disabled" yaml:"disabled"`
}

var _ option.Option = (*KubeProxyOptionsWithoutSelectors)(nil)

// Validate validates that option configurations are correctly defined.
func (o KubeProxyOptionsWithoutSelectors) Validate(_ *field.Path) field.ErrorList {
	return nil
}

// KubeProxyOptions contains options for kube-proxy rules
type KubeProxyOptions struct {
	*option.ClusterObjectSelector
	Disabled bool `json:"disabled" yaml:"disabled"`
}

var _ option.Option = (*KubeProxyOptions)(nil)

// Validate validates that option configurations are correctly defined.
func (o KubeProxyOptions) Validate(fldPath *field.Path) field.ErrorList {
	if o.ClusterObjectSelector != nil {
		return o.ClusterObjectSelector.Validate(fldPath)
	}
	return nil
}
