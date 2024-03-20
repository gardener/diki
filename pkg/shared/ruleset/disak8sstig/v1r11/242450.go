// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	intutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ rule.Rule = &Rule242450{}

type Rule242450 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242450
	Logger     provider.Logger
}

type Options242450 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
	*option.FileOwnerOptions
}

var _ option.Option = (*Options242450)(nil)

func (o Options242450) Validate() field.ErrorList {
	var allErrs = option.ValidateLabelNames(o.NodeGroupByLabels, field.NewPath("nodeGroupByLabels"))
	return append(allErrs, o.FileOwnerOptions.Validate()...)
}

func (r *Rule242450) ID() string {
	return ID242450
}

func (r *Rule242450) Name() string {
	return "The Kubernetes Kubelet certificate authority must be owned by root (MEDIUM 242450)"
}

func (r *Rule242450) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	options := option.FileOwnerOptions{}
	nodeLabels := []string{}

	if r.Options != nil {
		if r.Options.FileOwnerOptions != nil {
			options = *r.Options.FileOwnerOptions
		}
		if r.Options.NodeGroupByLabels != nil {
			nodeLabels = slices.Clone(r.Options.NodeGroupByLabels)
		}
	}
	if len(options.ExpectedFileOwner.Users) == 0 {
		options.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(options.ExpectedFileOwner.Groups) == 0 {
		options.ExpectedFileOwner.Groups = []string{"0"}
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

	for _, node := range selectedNodes {
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
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

		rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		if len(rawKubeletCommand) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrived", execPodTarget))
			continue
		}

		kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, podExecutor, rawKubeletCommand)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet config: %s", err.Error()), execPodTarget))
			continue
		}

		var kubeletClientCAFile string
		switch {
		case kubeletConfig.Authentication.X509.ClientCAFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file not set.", execPodTarget))
			continue
		case strings.TrimSpace(*kubeletConfig.Authentication.X509.ClientCAFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file is empty.", execPodTarget))
			continue
		default:
			kubeletClientCAFile = *kubeletConfig.Authentication.X509.ClientCAFile
		}

		fileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, kubeletClientCAFile)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		target := rule.NewTarget("kind", "node", "name", node.Name, "details", fmt.Sprintf("filePath: %s", kubeletClientCAFile))
		checkResults = append(checkResults,
			intutils.MatchFileOwnersCases(fileStats, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, target)...)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
