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
	"github.com/gardener/diki/pkg/provider/gardener"
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
	Logger                 *slog.Logger
}

func (r *RulePodFiles) ID() string {
	return IDPodFiles
}

func (r *RulePodFiles) Name() string {
	return "Config files for pod components must have required permissions and owners (242405, 242408, 242445, 242446, 242447, 242448, 242459)"
}

func (r *RulePodFiles) Run(ctx context.Context) (rule.RuleResult, error) {
	mandatoryComponentsSeed := map[string][]string{
		"ETCD Main":               {"instance", "etcd-main"},      // rules 242445, 242459
		"ETCD Events":             {"instance", "etcd-events"},    // rules 242445, 242459
		"Kube API Server":         {"role", "apiserver"},          // rule 242446
		"Kube Controller Manager": {"role", "controller-manager"}, // rule 242446
		"Kube Scheduler":          {"role", "scheduler"},          // rule 242446
	}
	mandatoryComponentsShoot := map[string][]string{
		"Kube Proxy": {"role", "proxy"}, // rules 242447, 242448
	}
	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

	seedTarget := gardener.NewTarget("cluster", "seed")
	shootTarget := gardener.NewTarget("cluster", "shoot")
	gardenerRoleControlplaneReq, err := labels.NewRequirement(v1beta1constants.GardenRole, selection.Equals, []string{"controlplane"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget())), nil
	}

	seedPodSelector := labels.NewSelector().Add(*gardenerRoleControlplaneReq)
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, seedPodSelector, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	checkResults := r.checkPods(ctx, seedTarget, image.String(), r.ControlPlaneClient, r.ControlPlanePodContext, seedPods, mandatoryComponentsSeed)

	managedByGardenerReq, err := labels.NewRequirement(resourcesv1alpha1.ManagedBy, selection.Equals, []string{"gardener"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget())), nil
	}

	gardenerRoleSystemComponentReq, err := labels.NewRequirement(v1beta1constants.GardenRole, selection.Equals, []string{"system-component"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget())), nil
	}

	shootPodSelector := labels.NewSelector().Add(*managedByGardenerReq).Add(*gardenerRoleSystemComponentReq)
	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", shootPodSelector, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))), nil
	}

	shootCheckResults := r.checkPods(ctx, shootTarget, image.String(), r.ClusterClient, r.ClusterPodContext, shootPods, mandatoryComponentsShoot)

	checkResults = append(checkResults, shootCheckResults...)

	if len(mandatoryComponentsSeed)+len(mandatoryComponentsShoot) > 0 {
		checkResults = make([]rule.CheckResult, 0, len(mandatoryComponentsSeed)+len(mandatoryComponentsShoot))

		for mandatoryComponentSeed := range mandatoryComponentsSeed {
			checkResults = append(checkResults, rule.FailedCheckResult("Mandatory Component not found!", seedTarget.With("details", fmt.Sprintf("missing %s", mandatoryComponentSeed))))
		}

		for mandatoryComponentShoot := range mandatoryComponentsShoot {
			checkResults = append(checkResults, rule.FailedCheckResult("Mandatory Component not found!", shootTarget.With("details", fmt.Sprintf("missing %s", mandatoryComponentShoot))))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *RulePodFiles) checkPods(ctx context.Context, clusterTarget gardener.Target, image string, c client.Client, podContext pod.PodContext, pods []corev1.Pod, mandatoryComponents map[string][]string) []rule.CheckResult {
	groupedPods, checkResults := utils.SelectPodOfReferenceGroup(pods, clusterTarget)

	for nodeName, pods := range groupedPods {
		checkResultsForNodePods := r.checkNodePods(ctx, clusterTarget, image, nodeName, c, podContext, pods, mandatoryComponents)
		checkResults = append(checkResults, checkResultsForNodePods...)
	}
	return checkResults
}

func (r *RulePodFiles) checkNodePods(ctx context.Context, clusterTarget gardener.Target, image, nodeName string, c client.Client, podContext pod.PodContext, nodePods []corev1.Pod, mandatoryComponents map[string][]string) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
	execPodTarget := clusterTarget.With("name", podName, "namespace", "kube-system", "kind", "pod")

	var podExecutor pod.PodExecutor
	var err error
	additionalLabels := map[string]string{
		gardener.LabelInstanceID: r.InstanceID,
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
	clusterTarget gardener.Target,
	mandatoryComponents map[string][]string,
	execPodTarget gardener.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	expectedFileOwnerUsers := []string{}
	expectedFileOwnerGroups := []string{}
	for component, pair := range mandatoryComponents {
		key := pair[0]
		value := pair[1]
		if metav1.HasLabel(pod.ObjectMeta, key) && pod.Labels[key] == value {
			delete(mandatoryComponents, component)
			expectedFileOwnerUsers = []string{"0", "65532"}
			expectedFileOwnerGroups = []string{"0", "65532", "65534"}
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
