// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	lakomapiv1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	lakomconst "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule1003{}
	_ rule.Severity = &Rule1003{}
)

type Rule1003 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule1003) ID() string {
	return "1003"
}

func (r *Rule1003) Name() string {
	return "Shoot clusters must have the Lakom extension configured."
}

func (r *Rule1003) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule1003) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var (
		extensionIndex = slices.IndexFunc(shoot.Spec.Extensions, func(shootSpecExtension gardencorev1beta1.Extension) bool {
			return shootSpecExtension.Type == lakomconst.ExtensionType
		})
		extensionDisabled                         = extensionIndex >= 0 && shoot.Spec.Extensions[extensionIndex].Disabled != nil && *shoot.Spec.Extensions[extensionIndex].Disabled
		extensionLabelValue, extensionLabelExists = shoot.Labels["extensions.extensions.gardener.cloud/"+lakomconst.ExtensionType]
	)

	switch {
	case !extensionLabelExists:
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Extension %s is not configured for the shoot cluster.", lakomconst.ExtensionType), rule.NewTarget())), nil
	case extensionLabelValue == "true" && !extensionDisabled && extensionIndex >= 0:
		var (
			lakomExtension = shoot.Spec.Extensions[extensionIndex]
			lakomConfig    = &lakomapiv1alpha1.LakomConfig{}
			scheme         = runtime.NewScheme()
		)

		if lakomExtension.ProviderConfig == nil {
			return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Extension %s is not configured for the shoot cluster.", lakomconst.ExtensionType), rule.NewTarget())), nil
		}

		if err := lakomapiv1alpha1.AddToScheme(scheme); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}

		_, _, err := serializer.NewCodecFactory(scheme).UniversalDeserializer().Decode(lakomExtension.ProviderConfig.Raw, nil, lakomConfig)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}

		if lakomConfig.TrustedKeysResourceName == nil || len(*lakomConfig.TrustedKeysResourceName) == 0 {
			return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Extension %s does not configure trusted keys.", lakomconst.ExtensionType), rule.NewTarget())), nil
		}

		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Extension %s configures trusted keys.", lakomconst.ExtensionType), rule.NewTarget())), nil
	case extensionLabelValue == "true" && !extensionDisabled:
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Extension %s is not configured for the shoot cluster.", lakomconst.ExtensionType), rule.NewTarget())), nil
	case extensionLabelValue == "true" && extensionDisabled:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Extension %s is disabled in the shoot spec and enabled in labels.", lakomconst.ExtensionType), rule.NewTarget())), nil
	default:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Extension %s has unexpected label value: %s.", lakomconst.ExtensionType, extensionLabelValue), rule.NewTarget())), nil
	}
}
