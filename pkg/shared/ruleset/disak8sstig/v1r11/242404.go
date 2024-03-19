// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"slices"

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

var _ rule.Rule = &Rule242404{}

type Rule242404 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242404
	Logger     provider.Logger
}

type Options242404 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

func (o Options242404) Validate() field.ErrorList {
	return option.ValidateLabelNames(o.NodeGroupByLabels, field.NewPath("nodeGroupByLabels"))
}

func (r *Rule242404) ID() string {
	return ID242404
}

func (r *Rule242404) Name() string {
	return "Kubernetes Kubelet must deny hostname override (MEDIUM 242404)"
}

func (r *Rule242404) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	nodeLabels := []string{}

	if r.Options != nil && r.Options.NodeGroupByLabels != nil {
		nodeLabels = slices.Clone(r.Options.NodeGroupByLabels)
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(pods, nodes)
	selectedNodes, checks := kubeutils.SelectNodes(nodes, nodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	for _, node := range selectedNodes {
		checkResult := r.checkNode(ctx, node, image.String())
		checkResults = append(checkResults, checkResult)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242404) checkNode(ctx context.Context, node corev1.Node, privPodImage string) rule.CheckResult {
	target := rule.NewTarget("kind", "node", "name", node.Name)

	podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
	podTarget := rule.NewTarget("kind", "pod", "namespace", "kube-system", "name", podName)

	defer func() {
		if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	additionalLabels := map[string]string{
		pod.LabelInstanceID: r.InstanceID,
	}
	podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", privPodImage, node.Name, additionalLabels))
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	const hostnameOverrideFlag = "hostname-override"

	// hostname-override does not exist in the kubelet config file. We can check if the hostname-override flag is set to validate the rule. ref https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
	if kubeutils.IsFlagSet(rawKubeletCommand, hostnameOverrideFlag) {
		return rule.FailedCheckResult(fmt.Sprintf("Flag %s set.", hostnameOverrideFlag), target)
	}

	return rule.PassedCheckResult(fmt.Sprintf("Flag %s not set.", hostnameOverrideFlag), target)
}
