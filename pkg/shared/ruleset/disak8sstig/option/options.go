// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	"strconv"

	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Option that can be validated in order to ensure
// that configurations are correctly defined
type Option interface {
	Validate() field.ErrorList
}

// PodSelector contains generalized options for matching entities by their attribute labels
type PodSelector struct {
	PodMatchLabels       map[string]string `json:"podMatchLabels" yaml:"podMatchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
}

var _ Option = (*PodSelector)(nil)

// Validate validates that option configurations are correctly defined
func (e PodSelector) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("")
	)

	if len(e.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("namespaceMatchLabels"), "must not be empty"))
	}

	if len(e.PodMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("podMatchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(e.NamespaceMatchLabels, rootPath.Child("namespaceMatchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(e.PodMatchLabels, rootPath.Child("podMatchLabels"))...)
	return allErrs
}

// FileOwnerOptions contains expected user and group owners for files
type FileOwnerOptions struct {
	ExpectedFileOwner ExpectedOwner `json:"expectedFileOwner" yaml:"expectedFileOwner"`
}

var _ Option = (*FileOwnerOptions)(nil)

// ExpectedOwner contains expected user and group owners
type ExpectedOwner struct {
	Users  []string `json:"users" yaml:"users"`
	Groups []string `json:"groups" yaml:"groups"`
}

// Validate validates that option configurations are correctly defined
func (o FileOwnerOptions) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("expectedFileOwner")
	)
	for _, user := range o.ExpectedFileOwner.Users {
		userID, err := strconv.ParseInt(user, 10, 64)
		if err != nil {
			allErrs = append(allErrs, field.InternalError(rootPath.Child("users"), err))
			continue
		}
		for _, msg := range validation.IsValidUserID(userID) {
			allErrs = append(allErrs, field.Invalid(rootPath.Child("users"), user, msg))
		}
	}

	for _, group := range o.ExpectedFileOwner.Groups {
		groupID, err := strconv.ParseInt(group, 10, 64)
		if err != nil {
			allErrs = append(allErrs, field.InternalError(rootPath.Child("groups"), err))
			continue
		}
		for _, msg := range validation.IsValidGroupID(groupID) {
			allErrs = append(allErrs, field.Invalid(rootPath.Child("groups"), group, msg))
		}
	}
	return allErrs
}

// Options242414 contains options for rule 242414
type Options242414 struct {
	AcceptedPods []AcceptedPods242414 `json:"acceptedPods" yaml:"acceptedPods"`
}

var _ Option = (*Options242414)(nil)

// AcceptedPods242414 contains option specifications for accepted pods
type AcceptedPods242414 struct {
	PodSelector
	Justification string  `json:"justification" yaml:"justification"`
	Ports         []int32 `json:"ports" yaml:"ports"`
}

// Validate validates that option configurations are correctly defined
func (o Options242414) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedPods")
	)
	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate()...)
		if len(p.Ports) == 0 {
			allErrs = append(allErrs, field.Required(rootPath.Child("ports"), "must not be empty"))
		}
		for _, port := range p.Ports {
			if port < 0 {
				allErrs = append(allErrs, field.Invalid(rootPath.Child("ports"), port, "must not be lower than 0"))
			}
		}
	}
	return allErrs
}

// Options242415 contains options for rule 242415
type Options242415 struct {
	AcceptedPods []AcceptedPods242415 `json:"acceptedPods" yaml:"acceptedPods"`
}

var _ Option = (*Options242415)(nil)

// AcceptedPods242415 contains option specifications for accepted pods
type AcceptedPods242415 struct {
	PodSelector
	Justification        string   `json:"justification" yaml:"justification"`
	EnvironmentVariables []string `json:"environmentVariables" yaml:"environmentVariables"`
}

// Validate validates that option configurations are correctly defined
func (o Options242415) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedPods")
	)
	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate()...)
		if len(p.EnvironmentVariables) == 0 {
			allErrs = append(allErrs, field.Required(rootPath.Child("environmentVariables"), "must not be empty"))
		}
		for _, env := range p.EnvironmentVariables {
			for _, msg := range validation.IsEnvVarName(env) {
				allErrs = append(allErrs, field.Invalid(rootPath.Child("environmentVariables"), env, msg))
			}
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

// KubeProxyOptions contains options for kube-proxy rules
type KubeProxyOptions struct {
	KubeProxyDisabled bool `json:"kubeProxyDisabled" yaml:"kubeProxyDisabled"`
}
