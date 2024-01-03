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

var _ rule.Rule = &Rule242451{}

type Rule242451 struct {
	InstanceID        string
	ClusterPodContext pod.PodContext
	Logger            *slog.Logger
}

func (r *Rule242451) ID() string {
	return ID242451
}

func (r *Rule242451) Name() string {
	return "The Kubernetes component PKI must be owned by root (MEDIUM 242451)"
}

func (r *Rule242451) Run(ctx context.Context) (rule.RuleResult, error) {
	expectedFileOwnerUsers := []string{"0"}
	expectedFileOwnerGroups := []string{"0"}

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

	target := rule.NewTarget("cluster", "shoot", "details", "filePath: /var/lib/kubelet/pki")
	if pkiAllStatsRaw, err := podExecutor.Execute(ctx, "/bin/sh", `find /var/lib/kubelet/pki -exec stat -Lc "%a %u %g %n" {} \;`); err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), execPodTarget)), nil
	} else if len(pkiAllStatsRaw) == 0 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("Stats not found", target)), nil
	} else {
		checkResults := []rule.CheckResult{}
		pkiAllStats := strings.Split(strings.TrimSpace(pkiAllStatsRaw), "\n")
		for _, pkiAllStat := range pkiAllStats {
			statSlice := strings.Split(pkiAllStat, " ")

			checkResults = append(checkResults, utils.MatchFileOwnersCases(statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
				expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
		}

		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: checkResults,
		}, nil
	}
}
