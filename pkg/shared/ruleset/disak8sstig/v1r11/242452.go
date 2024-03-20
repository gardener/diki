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

var _ rule.Rule = &Rule242452{}

type Rule242452 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242452
	Logger     provider.Logger
}

type Options242452 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

var _ option.Option = (*Options242452)(nil)

func (o Options242452) Validate() field.ErrorList {
	return option.ValidateLabelNames(o.NodeGroupByLabels, field.NewPath("nodeGroupByLabels"))
}

func (r *Rule242452) ID() string {
	return ID242452
}

func (r *Rule242452) Name() string {
	return "The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive (MEDIUM 242452)"
}

func (r *Rule242452) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	expectedFilePermissionsMax := "644"
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

		rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		if len(rawKubeletCommand) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("kubelet command not retrived", execPodTarget))
			continue
		}

		var (
			// TODO: extract this function and reuse it across rules
			getFlagValue = func(rawCommand, flag string) (string, error) {
				valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawCommand, " "), flag)

				if len(valueSlice) == 0 {
					return "", nil
				}
				if len(valueSlice) > 1 {
					return "", fmt.Errorf("kubelet %s flag has been set more than once", flag)
				}
				return valueSlice[0], nil
			}
			selectedFilePaths []string
			kubeconfigPath    string
			configPath        string
		)
		if kubeconfigPath, err = getFlagValue(rawKubeletCommand, "kubeconfig"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
		} else if len(kubeconfigPath) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Kubelet does not have set kubeconfig", nodeTarget))
		} else {
			selectedFilePaths = append(selectedFilePaths, kubeconfigPath)
		}

		if configPath, err = getFlagValue(rawKubeletCommand, "config"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
		} else if len(configPath) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Kubelet does not use config file", nodeTarget))
		} else {
			selectedFilePaths = append(selectedFilePaths, configPath)
		}

		for _, filePath := range selectedFilePaths {
			fileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, filePath)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
				continue
			}

			target := rule.NewTarget("kind", "node", "name", node.Name, "details", fmt.Sprintf("filePath: %s", fileStats.Path))
			exceedFilePermissions, err := intutils.ExceedFilePermissions(fileStats.Permissions, expectedFilePermissionsMax)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
				continue
			}

			if exceedFilePermissions {
				detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileStats.Path, fileStats.Permissions, expectedFilePermissionsMax))
				checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
				continue
			}

			detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileStats.Path, fileStats.Permissions))
			checkResults = append(checkResults, rule.PassedCheckResult("File has expected permissions", detailedTarget))
		}

	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
