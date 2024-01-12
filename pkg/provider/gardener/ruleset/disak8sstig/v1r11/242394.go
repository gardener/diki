// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242394{}

type Rule242394 struct {
	InstanceID        string
	ClusterPodContext pod.PodContext
	Logger            *slog.Logger
}

func (r *Rule242394) ID() string {
	return ID242394
}

func (r *Rule242394) Name() string {
	return "Kubernetes Worker Nodes must not have the sshd service enabled (MEDIUM 242394)"
}

func (r *Rule242394) Run(ctx context.Context) (rule.RuleResult, error) {
	target := rule.NewTarget("cluster", "shoot")
	podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	additionalLabels := map[string]string{
		pod.LabelInstanceID: r.InstanceID,
	}
	clusterPodExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), "", additionalLabels))
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	commandResult, err := clusterPodExecutor.Execute(ctx, "/bin/sh", `ss -tulpn | grep "LISTEN" | grep -E ":22(\s|$)" || true`)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}
	if strings.TrimSpace(commandResult) != "" {
		return rule.SingleCheckResult(r, rule.FailedCheckResult("SSH daemon started on port 22", target)), nil
	}

	commandResult, err = clusterPodExecutor.Execute(ctx, "/bin/sh", `systemctl is-enabled sshd || true`)
	if err != nil {
		if strings.HasSuffix(strings.TrimSpace(strings.ToLower(err.Error())), "no such file or directory") {
			return rule.SingleCheckResult(r, rule.PassedCheckResult("SSH daemon service not installed", target)), nil
		}

		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if strings.TrimSpace(strings.ToLower(commandResult)) == "alias" {
		return rule.SingleCheckResult(r, rule.FailedCheckResult("SSH daemon enabled", target)), nil
	}
	return rule.SingleCheckResult(r, rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", target)), nil
}