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
	kubectlversion "k8s.io/kubectl/pkg/cmd/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
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

	constraintK8s, err := semver.NewConstraint("< 1.12.9")
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	slices.SortFunc(selectedNodes, func(n1, n2 corev1.Node) int {
		return cmp.Compare(n1.Name, n2.Name)
	})

	for _, node := range selectedNodes {
		checkResults = append(checkResults,
			r.checkKubectl(ctx, node.Name, image.String(), constraintK8s))
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242396) checkKubectl(
	ctx context.Context,
	nodeName, imageName string,
	constraintK8s *semver.Constraints,
) rule.CheckResult {
	var (
		kubectlVersion   kubectlversion.Version
		podName          = fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
		nodeTarget       = rule.NewTarget("kind", "node", "name", nodeName)
		execPodTarget    = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), execPodTarget)
	}

	commandResult, err := podExecutor.Execute(ctx, "/bin/sh", `kubectl version --client --output=json`)
	if err != nil {
		if strings.Contains(err.Error(), "command terminated with exit code 127") {
			return rule.SkippedCheckResult("Kubectl command could not be found (or not installed)", nodeTarget)
		}

		return rule.ErroredCheckResult(err.Error(), execPodTarget)
	}

	err = json.Unmarshal([]byte(commandResult), &kubectlVersion)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), nodeTarget)
	}

	if kubectlVersion.ClientVersion == nil || len(kubectlVersion.ClientVersion.GitVersion) == 0 {
		return rule.ErroredCheckResult("kubectl client version not preset in output", execPodTarget.With("output", commandResult))
	}

	clientVersion, err := semver.NewVersion(kubectlVersion.ClientVersion.GitVersion)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), nodeTarget)
	}

	if constraintK8s.Check(clientVersion) {
		return rule.FailedCheckResult("Node uses not allowed kubectl version", nodeTarget.With("details", fmt.Sprintf("Kubectl client version %s", clientVersion.String())))
	}

	return rule.PassedCheckResult("Node uses allowed kubectl version", nodeTarget.With("details", fmt.Sprintf("Kubectl client version %s", clientVersion.String())))
}
