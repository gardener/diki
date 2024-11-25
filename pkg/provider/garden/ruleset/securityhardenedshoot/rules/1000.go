// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule     = &Rule1000{}
	_ rule.Severity = &Rule1000{}
	_ option.Option = &Options1000{}
)

type Extension1000 struct {
	Type string `json:"type" yaml:"type"`
}

type Options1000 struct {
	Extensions []Extension1000 `json:"extensions" yaml:"extensions"`
}

func (o Options1000) Validate() field.ErrorList {
	var (
		allErrs  = field.ErrorList{}
		rootPath = field.NewPath("extensions")
	)

	for _, extension := range o.Extensions {
		if len(extension.Type) == 0 {
			allErrs = append(allErrs, field.Required(rootPath.Child("type"), "must not be empty"))
		}
	}
	return allErrs
}

type Rule1000 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
	Options        *Options1000
}

func (r *Rule1000) ID() string {
	return "1000"
}

func (r *Rule1000) Name() string {
	return "Shoot clusters should enable required extensions. This rule can be configured as per organisation's requirements in order to check if required extensions are enabled for the shoot cluster."
}

func (r *Rule1000) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule1000) Run(ctx context.Context) (rule.RuleResult, error) {

	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	if r.Options == nil || len(r.Options.Extensions) == 0 {
		return rule.Result(r, rule.PassedCheckResult("There are no configured extensions to be evaluated.", rule.NewTarget())), nil
	}

	if shoot.Spec.Extensions == nil {
		return rule.Result(r, rule.FailedCheckResult("There are no configured extensions available on the shoot cluster.", rule.NewTarget())), nil
	}

	var checkResults = []rule.CheckResult{}

	for _, extensionTypeFromOption := range r.Options.Extensions {
		extensionTypeIndex := slices.IndexFunc(shoot.Spec.Extensions, func(extension gardencorev1beta1.Extension) bool {
			return extension.Type == extensionTypeFromOption.Type
		})

		if extensionTypeIndex < 0 {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Extension %s is not configured for the shoot cluster.", extensionTypeFromOption.Type), rule.NewTarget()))
		} else {
			if shoot.Spec.Extensions[extensionTypeIndex].Disabled == nil || !*(shoot.Spec.Extensions[extensionTypeIndex].Disabled) {
				checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Extension %s is enabled for the shoot cluster.", extensionTypeFromOption.Type), rule.NewTarget()))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Extension %s is disabled for the shoot cluster.", extensionTypeFromOption.Type), rule.NewTarget()))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
