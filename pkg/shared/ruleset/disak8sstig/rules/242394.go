// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ rule.Rule = &Rule242394{}

type Rule242394 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242394
	Logger     provider.Logger
}

type Options242394 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

var _ option.Option = (*Options242394)(nil)

func (o Options242394) Validate() field.ErrorList {
	return option.ValidateLabelNames(o.NodeGroupByLabels, field.NewPath("nodeGroupByLabels"))
}

func (r *Rule242394) ID() string {
	return ID242394
}

func (r *Rule242394) Name() string {
	return "Kubernetes Worker Nodes must not have the sshd service enabled (MEDIUM 242394)"
}

func (r *Rule242394) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	nodeLabels := []string{}

	if r.Options != nil && r.Options.NodeGroupByLabels != nil {
		nodeLabels = slices.Clone(r.Options.NodeGroupByLabels)
	}

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}
	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(pods, nodes)
	selectedNodes, checks := kubeutils.SelectNodes(nodes, nodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	if len(selectedNodes) == 0 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget())), nil
	}

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	slices.SortFunc(selectedNodes, func(n1, n2 corev1.Node) int {
		return cmp.Compare(n1.Name, n2.Name)
	})

	for _, node := range selectedNodes {
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
		nodeTarget := rule.NewTarget("kind", "node", "name", node.Name)
		execPodTarget := rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		defer func() {
			if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
				r.Logger.Error(err.Error())
			}
		}()
		additionalLabels := map[string]string{
			pod.LabelInstanceID: r.InstanceID,
		}
		podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), node.Name, additionalLabels))
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		commandResult, err := podExecutor.Execute(ctx, "/bin/sh", `ss -tulpn | grep "LISTEN" | grep -E ":22(\s|$)" || true`)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}
		if strings.TrimSpace(commandResult) != "" {
			checkResults = append(checkResults, rule.FailedCheckResult("SSH daemon started on port 22", nodeTarget))
			continue
		}

		commandResult, err = podExecutor.Execute(ctx, "/bin/sh", `systemctl is-enabled sshd || true`)
		if err != nil {
			if strings.HasSuffix(strings.TrimSpace(strings.ToLower(err.Error())), "no such file or directory") {
				checkResults = append(checkResults, rule.PassedCheckResult("SSH daemon service not installed", nodeTarget))
			} else {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}
			continue
		}
		if strings.TrimSpace(strings.ToLower(commandResult)) == "alias" {
			checkResults = append(checkResults, rule.FailedCheckResult("SSH daemon enabled", nodeTarget))
			continue
		}
		checkResults = append(checkResults, rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", nodeTarget))
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
