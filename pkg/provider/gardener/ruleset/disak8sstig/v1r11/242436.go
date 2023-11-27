// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242436{}

type Rule242436 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242436) ID() string {
	return ID242436
}

func (r *Rule242436) Name() string {
	return "Kubernetes API server must have the ValidatingAdmissionWebhook enabled (HIGH 242436)"
}

func (r *Rule242436) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName                = "kube-apiserver"
		enableAdmissionPlugins  = "enable-admission-plugins"
		disableAdmissionPlugins = "disable-admission-plugins"
	)
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	disableAdmissionPluginsSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, disableAdmissionPlugins)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(disableAdmissionPluginsSlice) > 1 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", disableAdmissionPlugins), target)), nil
	}
	if len(disableAdmissionPluginsSlice) == 1 && slices.Contains(strings.Split(disableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook") {
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", disableAdmissionPlugins), target)), nil
	}

	enableAdmissionPluginsSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, enableAdmissionPlugins)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// enable-admission-plugins defaults to allowed value ValidatingAdmissionWebhook
	// see https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
	switch {
	case len(enableAdmissionPluginsSlice) == 0:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", enableAdmissionPlugins), target)), nil
	case len(enableAdmissionPluginsSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", enableAdmissionPlugins), target)), nil
	case slices.Contains(strings.Split(enableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook"):
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", enableAdmissionPlugins), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", enableAdmissionPlugins), target)), nil
	}
}
