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
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242452{}

type Rule242452 struct {
	InstanceID        string
	ClusterPodContext pod.PodContext
	Logger            *slog.Logger
}

func (r *Rule242452) ID() string {
	return ID242452
}

func (r *Rule242452) Name() string {
	return "The Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242452)"
}

func (r *Rule242452) Run(ctx context.Context) (rule.RuleResult, error) {
	var kubeletConfigPath string
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

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet command: %s", err.Error()), execPodTarget)), nil
	}

	if len(rawKubeletCommand) > 0 {
		valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawKubeletCommand, " "), "config")

		if len(valueSlice) == 0 {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult("kubelet config flag has not been set", execPodTarget)), nil
		}
		if len(valueSlice) > 1 {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult("kubelet config flag has been set more than once", execPodTarget)), nil
		}

		kubeletConfigPath = valueSlice[0]
	} else {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrived", execPodTarget)), nil
	}

	target := rule.NewTarget("cluster", "shoot", "details", fmt.Sprintf("filePath: %s", kubeletConfigPath))
	statsRaw, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a %%u %%g %%n" %s`, kubeletConfigPath))
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), execPodTarget)), nil
	}
	if len(statsRaw) == 0 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("Stats not found", target)), nil
	}
	stat := strings.Split(strings.TrimSpace(statsRaw), "\n")[0]

	statSlice := strings.Split(stat, " ")
	expectedFilePermissionsMax := "644"
	filePermissions := statSlice[0]
	fileName := strings.Join(statSlice[3:], " ")

	exceedFilePermissions, err := utils.ExceedFilePermissions(filePermissions, expectedFilePermissionsMax)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if exceedFilePermissions {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileName, filePermissions, expectedFilePermissionsMax))
		return rule.SingleCheckResult(r, rule.FailedCheckResult("File has too wide permissions", detailedTarget)), nil
	}

	detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileName, filePermissions))
	return rule.SingleCheckResult(r, rule.PassedCheckResult("File has expected permissions", detailedTarget)), nil
}
