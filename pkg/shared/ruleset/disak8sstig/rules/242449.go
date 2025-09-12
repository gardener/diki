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
	_ rule.Rule     = &Rule242449{}
	_ rule.Severity = &Rule242449{}
)

type Rule242449 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242449
	Logger     provider.Logger
}

type Options242449 struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

var _ option.Option = (*Options242449)(nil)

func (o Options242449) Validate(fldPath *field.Path) field.ErrorList {
	return disaoption.ValidateLabelNames(o.NodeGroupByLabels, fldPath.Child("nodeGroupByLabels"))
}

func (r *Rule242449) ID() string {
	return ID242449
}

func (r *Rule242449) Name() string {
	return "The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive."
}

func (r *Rule242449) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242449) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults               []rule.CheckResult
		nodeLabels                 []string
		expectedFilePermissionsMax = "644"
	)

	if r.Options != nil && r.Options.NodeGroupByLabels != nil {
		nodeLabels = slices.Clone(r.Options.NodeGroupByLabels)
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
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
		execPodTarget := rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "Pod")
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
			checkResults = append(checkResults, rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrieved", execPodTarget))
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

		target := kubeutils.TargetWithK8sObject(rule.NewTarget("details", fmt.Sprintf("filePath: %s", kubeletClientCAFile)), metav1.TypeMeta{Kind: "Node"}, node.ObjectMeta)

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

	return rule.Result(r, checkResults...), nil
}
