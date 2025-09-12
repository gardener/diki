// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	"github.com/gardener/diki/pkg/shared/provider"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule     = &Rule242453{}
	_ rule.Severity = &Rule242453{}
)

type Rule242453 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242453
	Logger     provider.Logger
}

type Options242453 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
	*disaoption.FileOwnerOptions
}

var _ option.Option = (*Options242453)(nil)

func (o Options242453) Validate(fldPath *field.Path) field.ErrorList {
	allErrs := disaoption.ValidateLabelNames(o.NodeGroupByLabels, fldPath.Child("nodeGroupByLabels"))
	if o.FileOwnerOptions != nil {
		return append(allErrs, o.FileOwnerOptions.Validate(fldPath)...)
	}
	return allErrs
}

func (r *Rule242453) ID() string {
	return ID242453
}

func (r *Rule242453) Name() string {
	return "The Kubernetes kubelet KubeConfig file must be owned by root."
}

func (r *Rule242453) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242453) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults []rule.CheckResult
		nodeLabels   []string
		options      = disaoption.FileOwnerOptions{}
	)

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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}
	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NodeList"))), nil
	}

	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(pods, nodes)
	selectedNodes, checks := kubeutils.SelectNodes(nodes, nodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	if len(selectedNodes) == 0 {
		return rule.Result(r, rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget())), nil
	}

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	for _, node := range selectedNodes {
		var (
			selectedFilePaths []string
			podName           = fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
			nodeTarget        = kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Node"}, node.ObjectMeta)
			execPodTarget     = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "Pod")
		)
		defer func() {
			timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			if err := r.PodContext.Delete(timeoutCtx, podName, "kube-system"); err != nil {
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
			checkResults = append(checkResults, rule.ErroredCheckResult("kubelet command not retrieved", execPodTarget))
			continue
		}

		var kubeconfigPath string
		if kubeconfigPath, err = r.getKubeletFlagValue(rawKubeletCommand, "kubeconfig"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
		} else if len(kubeconfigPath) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Kubelet does not have set kubeconfig", nodeTarget))
		} else {
			selectedFilePaths = append(selectedFilePaths, kubeconfigPath)
		}

		var configPath string
		if configPath, err = r.getKubeletFlagValue(rawKubeletCommand, "config"); err != nil {
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

			detailedNodeTarget := nodeTarget.With("details", fmt.Sprintf("filePath: %s", fileStats.Path))
			checkResults = append(checkResults,
				intutils.MatchFileOwnersCases(fileStats, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, detailedNodeTarget)...)
		}

	}
	return rule.Result(r, checkResults...), nil
}

func (r *Rule242453) getKubeletFlagValue(rawCommand, flag string) (string, error) {
	valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawCommand, " "), flag)

	if len(valueSlice) == 0 {
		return "", nil
	}
	if len(valueSlice) > 1 {
		return "", fmt.Errorf("kubelet %s flag has been set more than once", flag)
	}
	return valueSlice[0], nil
}
