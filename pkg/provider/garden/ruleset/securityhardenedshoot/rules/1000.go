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

type Options1000 struct {
	Extensions []Extension `json:"extensions" yaml:"extensions"`
}

type Extension struct {
	Type string `json:"type" yaml:"type"`
}

func (o Options1000) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
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
	return "Shoot clusters should enable required extensions."
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
		return rule.Result(r, rule.PassedCheckResult("There are no required extensions.", rule.NewTarget())), nil
	}

	var checkResults []rule.CheckResult

	for _, extension := range r.Options.Extensions {
		extensionTypeIndex := slices.IndexFunc(shoot.Spec.Extensions, func(shootSpecExtension gardencorev1beta1.Extension) bool {
			return shootSpecExtension.Type == extension.Type
		})

		var (
			extensionTypeDisabled       = extensionTypeIndex >= 0 && shoot.Spec.Extensions[extensionTypeIndex].Disabled != nil && *shoot.Spec.Extensions[extensionTypeIndex].Disabled
			extensionTypeLabelKey       = fmt.Sprintf("extensions.extensions.gardener.cloud/%s", extension.Type)
			extensionTypeLabelValue, ok = shoot.Labels[extensionTypeLabelKey]
		)

		switch {
		case !ok:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Extension type %s is not configured for the shoot cluster.", extension.Type), rule.NewTarget()))
		case extensionTypeLabelValue == "true" && !extensionTypeDisabled:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Extension type %s is enabled for the shoot cluster.", extension.Type), rule.NewTarget()))
		case extensionTypeLabelValue == "true" && extensionTypeDisabled:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Extension type %s is disabled is the shoot spec and enabled in labels.", extension.Type), rule.NewTarget()))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Extension type %s has unexpected label value: %s.", extension.Type, extensionTypeLabelValue), rule.NewTarget()))
		}
	}

	return rule.Result(r, checkResults...), nil
}
