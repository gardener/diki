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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	intutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242400{}

type Rule242400 struct {
	InstanceID   string
	Client       client.Client
	V1RESTClient rest.Interface
	PodContext   pod.PodContext
	Options      *Options242400
	Logger       provider.Logger
}

type Options242400 struct {
	option.KubeProxyOptions
	KubeProxyMatchLabels map[string]string `json:"kubeProxyMatchLabels" yaml:"kubeProxyMatchLabels"`
}

var _ option.Option = (*Options242400)(nil)

func (o Options242400) Validate() field.ErrorList {
	return validation.ValidateLabels(o.KubeProxyMatchLabels, field.NewPath("kubeProxyMatchLabels"))
}

func (r *Rule242400) ID() string {
	return sharedrules.ID242400
}

func (r *Rule242400) Name() string {
	return "The Kubernetes API server must have Alpha APIs disabled (MEDIUM 242400)"
}

func (r *Rule242400) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "featureGates.AllAlpha"
	var (
		checkResults      []rule.CheckResult
		kubeProxySelector = labels.SelectorFromSet(labels.Set{"role": "proxy"})
	)

	if r.Options != nil && len(r.Options.KubeProxyMatchLabels) > 0 {
		kubeProxySelector = labels.SelectorFromSet(labels.Set(r.Options.KubeProxyMatchLabels))
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	// kubelet check
	for _, node := range nodes {
		target := rule.NewTarget("kind", "node", "name", node.Name)
		if !kubeutils.NodeReadyStatus(node) {
			checkResults = append(checkResults, rule.WarningCheckResult("Node is not in Ready state.", target))
			continue
		}

		kubeletConfig, err := kubeutils.GetNodeConfigz(ctx, r.V1RESTClient, node.Name)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
			continue
		}

		// featureGates.AllAlpha defaults to false. ref https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
		allAlpha, ok := kubeletConfig.FeatureGates["AllAlpha"]
		switch {
		case !ok:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target))
		case allAlpha:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target))
		}
	}

	// kube-proxy check
	if r.Options != nil && r.Options.KubeProxyDisabled {
		checkResults = append(checkResults, rule.AcceptedCheckResult("kube-proxy check is skipped.", rule.NewTarget()))
		return rule.Result(r, checkResults...), nil
	}

	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList")))
	} else {
		pods := []corev1.Pod{}
		for _, p := range allPods {
			if kubeProxySelector.Matches(labels.Set(p.Labels)) {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget("selector", kubeProxySelector.String())))
		} else {
			image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
			if err != nil {
				return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
			}
			image.WithOptionalTag(version.Get().GitVersion)

			nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)
			groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.NewTarget())
			checkResults = append(checkResults, checks...)
			for nodeName, pods := range groupedPods {
				checkResults = append(checkResults, r.checkKubeProxy(ctx, pods, nodeName, image.String())...)
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242400) checkKubeProxy(
	ctx context.Context,
	pods []corev1.Pod,
	nodeName, imageName string,
) []rule.CheckResult {
	const option = "featureGates.AllAlpha"
	var (
		checkResults            []rule.CheckResult
		additionalLabels        = map[string]string{pod.LabelInstanceID: r.InstanceID}
		podName                 = fmt.Sprintf("diki-%s-%s", r.ID(), sharedrules.Generator.Generate(10))
		execPodTarget           = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		kubeProxyContainerNames = []string{"kube-proxy", "proxy"}
	)

	defer func() {
		if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	execPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "kube-system",
		},
	}

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(execPod), execPod); err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	var (
		execContainerID     = execPod.Status.ContainerStatuses[0].ContainerID
		execBaseContainerID = strings.Split(execContainerID, "//")[1]
		execContainerPath   = fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", execBaseContainerID)
	)

	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, pod := range pods {
		podTarget := rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")

		rawKubeProxyCommand, err := kubeutils.GetContainerCommand(pod, kubeProxyContainerNames...)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
			continue
		}

		var configPath string
		configPathOptions := kubeutils.FindFlagValueRaw(strings.Split(rawKubeProxyCommand, " "), "config")
		switch {
		case len(configPathOptions) > 1:
			checkResults = append(checkResults, rule.ErroredCheckResult("option config set more than once in container command", podTarget))
			continue
		case len(configPathOptions) == 1:
			configPath = configPathOptions[0]
		default:
			configPath = ""
		}

		var allAlpha *bool
		if len(configPath) != 0 {
			kubeProxyContainerID, err := intutils.GetContainerID(pod, kubeProxyContainerNames...)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeProxyMounts, err := intutils.GetContainerMounts(ctx, execContainerPath, podExecutor, kubeProxyContainerID)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
				continue
			}

			configSourcePath, err := kubeutils.FindFileMountSource(configPath, kubeProxyMounts)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeProxyConfig, err := kubeutils.GetKubeProxyConfig(ctx, podExecutor, configSourcePath)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
				continue
			}

			if val, ok := kubeProxyConfig.FeatureGates["AllAlpha"]; ok {
				allAlpha = &val
			}
		} else {
			fgOptions := kubeutils.FindFlagValueRaw(strings.Split(rawKubeProxyCommand, " "), "feature-gates")

			allAlphaOptions := kubeutils.FindInnerValue(fgOptions, "AllAlpha")
			switch {
			case len(allAlphaOptions) > 1:
				checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s set more than once in container command.", option), podTarget))
				continue
			case len(allAlphaOptions) == 0:
				// Do nothing
			case allAlphaOptions[0] == "true":
				allAlpha = ptr.To(true)
			case allAlphaOptions[0] == "false":
				allAlpha = ptr.To(false)
			default:
				checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false' in container command.", option), podTarget))
				continue
			}
		}

		// featureGates.AllAlpha defaults to false. ref https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/
		switch {
		case allAlpha == nil:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), podTarget))
		case *allAlpha:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), podTarget))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), podTarget))
		}
	}
	return checkResults
}
