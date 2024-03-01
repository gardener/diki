// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
)

var _ rule.Rule = &Rule242396{}

type Rule242396 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242396
	Logger     provider.Logger
}

type Options242396 struct {
	GroupByLabels []string `json:"groupByLabels" yaml:"groupByLabels"`
}

func (r *Rule242396) ID() string {
	return ID242396
}

func (r *Rule242396) Name() string {
	return "Kubernetes Kubectl cp command must give expected access and results (MEDIUM 242396)"
}

func (r *Rule242396) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		nodeLabels   []string
		checkResults []rule.CheckResult
	)

	if r.Options != nil && r.Options.GroupByLabels != nil {
		nodeLabels = slices.Clone(r.Options.GroupByLabels)
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
		var (
			kubectlVersion   config.KubectlVersion
			podName          = fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
			nodeTarget       = rule.NewTarget("kind", "node", "name", node.Name)
			execPodTarget    = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
			additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
		)

		defer func() {
			if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
				r.Logger.Error(err.Error())
			}
		}()

		podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), node.Name, additionalLabels))
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		commandResult, err := podExecutor.Execute(ctx, "/bin/sh", `kubectl version --client --output=json`)
		if err != nil {
			if strings.Contains(err.Error(), "command terminated with exit code 127") {
				checkResults = append(checkResults, rule.SkippedCheckResult("Kubectl command could not be found (or not installed)", nodeTarget))
			} else {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}
			continue
		}

		err = json.Unmarshal([]byte(commandResult), &kubectlVersion)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), nodeTarget))
			continue
		}

		if len(kubectlVersion.ClientVersion.GitVersion) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("kubectl client version not preset in output", execPodTarget.With("output", commandResult)))
			continue
		}

		clientVersion, err := semver.NewVersion(kubectlVersion.ClientVersion.GitVersion)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), nodeTarget))
			continue
		}

		constraintK8s, err := semver.NewConstraint("< 1.12.9")
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), nodeTarget))
			continue
		}

		if constraintK8s.Check(clientVersion) {
			checkResults = append(checkResults, rule.FailedCheckResult("Node uses not allowed kubectl version", nodeTarget.With("details", fmt.Sprintf("Kubectl client version %s", clientVersion.String()))))
			continue
		}

		checkResults = append(checkResults, rule.PassedCheckResult("Node uses allowed kubectl version", nodeTarget.With("details", fmt.Sprintf("Kubectl client version %s", clientVersion.String()))))
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
