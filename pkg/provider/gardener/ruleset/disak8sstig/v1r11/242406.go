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
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242406{}

type Rule242406 struct {
	InstanceID        string
	ClusterPodContext pod.PodContext
	Logger            *slog.Logger
}

func (r *Rule242406) ID() string {
	return ID242406
}

func (r *Rule242406) Name() string {
	return "The Kubernetes kubelet configuration file must be owned by root (MEDIUM 242406)"
}

func (r *Rule242406) Run(ctx context.Context) (rule.RuleResult, error) {
	expectedFileOwnerUsers := []string{"0"}
	expectedFileOwnerGroups := []string{"0"}
	var kubeletServicePath string

	podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
	execPodTarget := rule.NewTarget("cluster", "shoot", "name", podName, "namespace", "kube-system", "kind", "pod")
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
	podExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), "", additionalLabels))
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), execPodTarget)), nil
	}

	if kubeletServicePath, err = podExecutor.Execute(ctx, "/bin/sh", "systemctl show -P FragmentPath kubelet.service"); err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet.service path: %s", err.Error()), execPodTarget)), nil
	}

	target := rule.NewTarget("cluster", "shoot", "details", fmt.Sprintf("filePath: %s", kubeletServicePath))
	statsRaw, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a %%u %%g %%n" %s`, kubeletServicePath))
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), execPodTarget)), nil
	}
	if len(statsRaw) == 0 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("Stats not found", target)), nil
	}
	stat := strings.Split(strings.TrimSpace(statsRaw), "\n")[0]

	statSlice := strings.Split(stat, " ")
	checkResults := utils.MatchFileOwnersCases(statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
		expectedFileOwnerUsers, expectedFileOwnerGroups, target)

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
