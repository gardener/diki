// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kapiName,
			Namespace: r.Namespace,
		},
	}

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	container, found := kubeutils.GetContainerFromDeployment(deployment, kapiName)
	if !found {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(fmt.Sprintf("deployment: %s does not contain container: %s", kapiName, kapiName), target)), nil
	}

	enableAdmissionPluginsSlice := kubeutils.FindFlagValueRaw(append(container.Command, container.Args...), enableAdmissionPlugins)
	disableAdmissionPluginsSlice := kubeutils.FindFlagValueRaw(append(container.Command, container.Args...), disableAdmissionPlugins)

	// enable-admission-plugins defaults to allowed value ValidatingAdmissionWebhook
	// see https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
	switch {
	case len(enableAdmissionPluginsSlice) == 0:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", enableAdmissionPlugins), target)), nil
	case len(enableAdmissionPluginsSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", enableAdmissionPlugins), target)), nil
	case len(disableAdmissionPluginsSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", disableAdmissionPlugins), target)), nil
	case len(disableAdmissionPluginsSlice) == 1 && slices.Contains(strings.Split(disableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook"):
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", disableAdmissionPlugins), target)), nil
	case slices.Contains(strings.Split(enableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook"):
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", enableAdmissionPlugins), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", enableAdmissionPlugins), target)), nil
	}
}
