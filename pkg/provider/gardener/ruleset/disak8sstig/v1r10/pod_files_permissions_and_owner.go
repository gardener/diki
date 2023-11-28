// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &RulePodFiles{}

type RulePodFiles struct {
	InstanceID             string
	ControlPlaneClient     client.Client
	ControlPlaneNamespace  string
	ControlPlanePodContext pod.PodContext
	ClusterClient          client.Client
	ClusterPodContext      pod.PodContext
	Options                *OptionsPodFiles
	Logger                 *slog.Logger
}

type OptionsPodFiles struct {
	ExpectedFileOwner ExpectedFileOwner `yaml:"expectedFileOwner"`
}

type ExpectedFileOwner struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

type component struct {
	name  string
	label string
	value string
	found bool
}

func (r *RulePodFiles) ID() string {
	return IDPodFiles
}

func (r *RulePodFiles) Name() string {
	return "Config files for pod components must have required permissions and owners (242405, 242408, 242445, 242446, 242447, 242448, 242459)"
}

func (r *RulePodFiles) Run(ctx context.Context) (rule.RuleResult, error) {
	mandatoryComponentsSeed := []*component{
		{name: "ETCD Main", label: "instance", value: "etcd-main"},                    // rules 242445, 242459
		{name: "ETCD Events", label: "instance", value: "etcd-events"},                // rules 242445, 242459
		{name: "Kube API Server", label: "role", value: "apiserver"},                  // rule 242446
		{name: "Kube Controller Manager", label: "role", value: "controller-manager"}, // rule 242446
		{name: "Kube Scheduler", label: "role", value: "scheduler"},                   // rule 242446
	}
	mandatoryComponentsShoot := []*component{
		{name: "Kube Proxy", label: "role", value: "proxy"}, // rules 242447, 242448
	}
	if r.Options == nil {
		r.Options = &OptionsPodFiles{}
	}
	if len(r.Options.ExpectedFileOwner.Users) == 0 {
		r.Options.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(r.Options.ExpectedFileOwner.Groups) == 0 {
		r.Options.ExpectedFileOwner.Groups = []string{"0"}
	}

	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

	seedTarget := rule.NewTarget("cluster", "seed")
	shootTarget := rule.NewTarget("cluster", "shoot")
	gardenerRoleControlplaneReq, err := labels.NewRequirement(v1beta1constants.GardenRole, selection.Equals, []string{"controlplane"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	seedAllPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}
	seedPodSelector := labels.NewSelector().Add(*gardenerRoleControlplaneReq)
	seedControlPlanePods := []corev1.Pod{}
	for _, p := range seedAllPods {
		if seedPodSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.ControlPlaneNamespace {
			seedControlPlanePods = append(seedControlPlanePods, p)
		}
	}

	seedNodes, err := kubeutils.GetNodes(ctx, r.ControlPlaneClient, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "nodeList"))), nil
	}

	checkResults := r.checkPods(ctx, seedTarget, image.String(), r.ControlPlaneClient, r.ControlPlanePodContext, seedAllPods, seedControlPlanePods, seedNodes, mandatoryComponentsSeed)

	managedByGardenerReq, err := labels.NewRequirement(resourcesv1alpha1.ManagedBy, selection.Equals, []string{"gardener"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	gardenerRoleSystemComponentReq, err := labels.NewRequirement(v1beta1constants.GardenRole, selection.Equals, []string{"system-component"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	shootAllPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))), nil
	}

	shootSystemPodSelector := labels.NewSelector().Add(*managedByGardenerReq).Add(*gardenerRoleSystemComponentReq)
	shootSystemComponetPods := []corev1.Pod{}
	for _, p := range shootAllPods {
		if shootSystemPodSelector.Matches(labels.Set(p.Labels)) {
			shootSystemComponetPods = append(shootSystemComponetPods, p)
		}
	}

	shootNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "nodeList"))), nil
	}

	shootCheckResults := r.checkPods(ctx, shootTarget, image.String(), r.ClusterClient, r.ClusterPodContext, shootAllPods, shootSystemComponetPods, shootNodes, mandatoryComponentsShoot)

	checkResults = append(checkResults, shootCheckResults...)

	for _, mandatoryComponentSeed := range mandatoryComponentsSeed {
		if !mandatoryComponentSeed.found {
			checkResults = append(checkResults, rule.FailedCheckResult("Mandatory Component not found!", seedTarget.With("details", fmt.Sprintf("missing %s", mandatoryComponentSeed.name))))
		}
	}

	for _, mandatoryComponentShoot := range mandatoryComponentsShoot {
		if !mandatoryComponentShoot.found {
			checkResults = append(checkResults, rule.FailedCheckResult("Mandatory Component not found!", shootTarget.With("details", fmt.Sprintf("missing %s", mandatoryComponentShoot.name))))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *RulePodFiles) checkPods(ctx context.Context, clusterTarget rule.Target, image string, c client.Client, podContext pod.PodContext, pods, selectedPods []corev1.Pod, nodes []corev1.Node, mandatoryComponents []*component) []rule.CheckResult {
	nodesAllocatablePods := utils.GetNodesAllocatablePodsNum(pods, nodes)
	groupedPods, checkResults := utils.SelectPodOfReferenceGroup(selectedPods, nodesAllocatablePods, clusterTarget)

	for nodeName, pods := range groupedPods {
		checkResultsForNodePods := r.checkNodePods(ctx, clusterTarget, image, nodeName, c, podContext, pods, mandatoryComponents)
		checkResults = append(checkResults, checkResultsForNodePods...)
	}
	return checkResults
}

func (r *RulePodFiles) checkNodePods(ctx context.Context, clusterTarget rule.Target, image, nodeName string, c client.Client, podContext pod.PodContext, nodePods []corev1.Pod, mandatoryComponents []*component) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
	execPodTarget := clusterTarget.With("name", podName, "namespace", "kube-system", "kind", "pod")

	var podExecutor pod.PodExecutor
	var err error
	additionalLabels := map[string]string{
		pod.LabelInstanceID: r.InstanceID,
	}

	defer func() {
		if err := podContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	podExecutor, err = podContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image, nodeName, additionalLabels))
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	execPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "kube-system",
		},
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(execPod), execPod); err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	execContainerID := execPod.Status.ContainerStatuses[0].ContainerID
	execBaseContainerID := strings.Split(execContainerID, "//")[1]
	execContainerPath := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", execBaseContainerID)

	for _, nodePod := range nodePods {
		nodePodTarget := clusterTarget.With("name", nodePod.Name, "namespace", nodePod.Namespace, "kind", "pod")
		for _, container := range nodePod.Spec.Containers {
			containerTraget := nodePodTarget.With("containerName", container.Name)
			found := false
			for _, status := range nodePod.Status.ContainerStatuses {
				if status.Name == container.Name {
					found = true
					containerID := status.ContainerID
					switch {
					case len(containerID) == 0:
						checkResults = append(checkResults, rule.ErroredCheckResult("Container not (yet) running", containerTraget))
					case strings.HasPrefix(containerID, "containerd://"):
						baseContainerID := strings.Split(containerID, "//")[1]
						checkResults = append(checkResults, r.checkContainerd(
							ctx,
							podExecutor,
							nodePod,
							container.Name,
							baseContainerID,
							execContainerPath,
							clusterTarget,
							mandatoryComponents,
							execPodTarget)...,
						)
					default:
						checkResults = append(checkResults, rule.ErroredCheckResult("Cannot handle container", containerTraget))
					}

				}
			}

			if !found {
				checkResults = append(checkResults, rule.ErroredCheckResult("Container not (yet) in status", containerTraget))
			}
		}
	}
	return checkResults
}

func (r *RulePodFiles) checkContainerd(
	ctx context.Context,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	containerName string,
	containerID string,
	execContainerPath string,
	clusterTarget rule.Target,
	mandatoryComponents []*component,
	execPodTarget rule.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	expectedFileOwnerUsers := []string{}
	expectedFileOwnerGroups := []string{}
	isMandatoryComponent := false
	for _, mandatoryComponents := range mandatoryComponents {
		if metav1.HasLabel(pod.ObjectMeta, mandatoryComponents.label) && pod.Labels[mandatoryComponents.label] == mandatoryComponents.value {
			mandatoryComponents.found = true
			isMandatoryComponent = true
			expectedFileOwnerUsers = r.Options.ExpectedFileOwner.Users
			expectedFileOwnerGroups = r.Options.ExpectedFileOwner.Groups
			break
		}
	}

	commandResult, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`%s/usr/local/bin/nerdctl --namespace k8s.io inspect --mode=native %s | jq -r .[0].Spec.mounts`, execContainerPath, containerID))
	if err != nil {
		return append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
	}

	mounts := []config.Mount{}
	err = json.Unmarshal([]byte(commandResult), &mounts)
	if err != nil {
		return append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
	}
	excludedSources := sets.New("/lib/modules", "/usr/share/ca-certificates", "/var/log/journal")

	for _, mount := range mounts {
		expectedFilePermissionsMax := "644"
		if strings.HasPrefix(mount.Source, "/") &&
			!r.matchHostPathSources(excludedSources, mount.Destination, containerName, &pod) &&
			r.isMountRequiredByContainer(mount.Destination, containerName, &pod) &&
			mount.Destination != "/dev/termination-log" {
			stats, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -type f -exec stat -Lc "%%a %%u %%g %%n" {} \;`, mount.Source))
			if err != nil {
				return append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}

			if len(stats) == 0 {
				continue
			}
			statsSlice := strings.Split(strings.TrimSpace(stats), "\n")

			fileTarget := clusterTarget.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
			if metav1.HasLabel(pod.ObjectMeta, "name") && pod.Labels["name"] == "etcd" && strings.Contains(mount.Destination, "etcd/data") {
				expectedFilePermissionsMax = "600"
			}

			for _, stat := range statsSlice {
				statSlice := strings.Split(stat, " ")

				if isMandatoryComponent && strings.HasSuffix(strings.Join(statSlice[3:], " "), ".key") {
					// rule 242467
					// Gardener control plane components run as `nonroot` user `65532`, since we can change the group owener but
					// cannot easily change the user owner of secret files we do not check for `0600` permission but instead for `0640`.
					checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
						"640", expectedFileOwnerUsers, expectedFileOwnerGroups, fileTarget)...)
					continue
				}

				checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
					expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups, fileTarget)...)
			}
		}
	}

	return checkResults
}

func (r *RulePodFiles) isMountRequiredByContainer(destination, containerName string, pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != containerName {
			continue
		}
		if containsDestination := slices.ContainsFunc(container.VolumeMounts, func(volumeMount corev1.VolumeMount) bool {
			return volumeMount.MountPath == destination
		}); containsDestination {
			return true
		}
	}
	return false
}

func (r *RulePodFiles) matchHostPathSources(sources sets.Set[string], destination, containerName string, pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != containerName {
			continue
		}
		volumeMountIdx := slices.IndexFunc(container.VolumeMounts, func(volumeMount corev1.VolumeMount) bool {
			return volumeMount.MountPath == destination
		})

		if volumeMountIdx < 0 {
			return false
		}

		volumeIdx := slices.IndexFunc(pod.Spec.Volumes, func(volume corev1.Volume) bool {
			return volume.Name == container.VolumeMounts[volumeMountIdx].Name
		})

		if volumeIdx < 0 {
			return false
		}

		volume := pod.Spec.Volumes[volumeIdx]

		return volume.HostPath != nil && sources.Has(volume.HostPath.Path)
	}
	return false
}
