// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

// GetWorkers returns all workers for a given namespace, or all namespaces if it's set to empty string "".
// It retrieves workers by portions set by limit.
func GetWorkers(ctx context.Context, c client.Client, namespace string, limit int64) ([]extensionsv1alpha1.Worker, error) {
	workerList := &extensionsv1alpha1.WorkerList{}
	workers := []extensionsv1alpha1.Worker{}

	for {
		if err := c.List(ctx, workerList, client.InNamespace(namespace), client.Limit(limit), client.Continue(workerList.Continue)); err != nil {
			return nil, err
		}

		workers = append(workers, workerList.Items...)

		if len(workerList.Continue) == 0 {
			return workers, nil
		}
	}
}

// AllocatableNode contains a single Node and whether it is in allocatable or not.
// An allocatable node is a node that is in ready state and has at least 1 allocatable spot.
type AllocatableNode struct {
	Node        *corev1.Node
	Allocatable bool
}

// GetSingleAllocatableNodePerWorker returns a map where the keys are the names of the worker pool and the values is a
// allocatable node of the worker pool. If no allocatable nodes are present for a given worker pool the value equals nil.
func GetSingleAllocatableNodePerWorker(workers []extensionsv1alpha1.Worker, nodes []corev1.Node, nodesAllocatablePods map[string]int) map[string]AllocatableNode {
	result := map[string]AllocatableNode{}

	for _, worker := range workers {
		for _, workerGroup := range worker.Spec.Pools {
			if workerGroup.Minimum == 0 && !anyNodesForWorkerGroup(workerGroup.Name, nodes) {
				continue
			}

			var allocatableNode *corev1.Node
			maxAllocatablePods := 0
			for _, node := range nodes {
				// find an allocatable node with the most allocatable spots for pods
				if node.ObjectMeta.Labels[v1beta1constants.LabelWorkerPool] == workerGroup.Name && kubeutils.NodeReadyStatus(node) &&
					maxAllocatablePods < nodesAllocatablePods[node.Name] {
					maxAllocatablePods = nodesAllocatablePods[node.Name]
					node := node
					allocatableNode = &node
				}
			}

			result[workerGroup.Name] = AllocatableNode{
				Node:        allocatableNode,
				Allocatable: allocatableNode != nil, // assign a nil not allocatable entry for the worker group if we could not find an allocatable node
			}
		}
	}

	return result
}

// ReadyNode contains a single Node and whether it is in Ready state or not
type ReadyNode struct {
	Node  *corev1.Node
	Ready bool
}

// GetSingleRunningNodePerWorker returns a map where the keys are the names of the worker pool and the values are the first
// ready node of the worker pool. If no ready nodes are present for a given worker pool the value equals nil.
func GetSingleRunningNodePerWorker(workers []extensionsv1alpha1.Worker, nodes []corev1.Node) map[string]ReadyNode {
	result := map[string]ReadyNode{}

	for _, worker := range workers {
		for _, workerGroup := range worker.Spec.Pools {
			if workerGroup.Minimum == 0 && !anyNodesForWorkerGroup(workerGroup.Name, nodes) {
				continue
			}

			var rn *corev1.Node
			for _, node := range nodes {
				// find the first ready node per worker group
				if node.ObjectMeta.Labels[v1beta1constants.LabelWorkerPool] == workerGroup.Name && kubeutils.NodeReadyStatus(node) {
					node := node
					rn = &node
					break
				}
			}

			result[workerGroup.Name] = ReadyNode{
				Node:  rn,
				Ready: rn != nil, // assign a nil not ready entry for the worker group if we could not find a ready node
			}
		}
	}

	return result
}

func anyNodesForWorkerGroup(workerGroupName string, nodes []corev1.Node) bool {
	for _, node := range nodes {
		if node.ObjectMeta.Labels[v1beta1constants.LabelWorkerPool] == workerGroupName {
			return true
		}
	}
	return false
}

// EqualSets checks if two slices contain exactly the same elements independent of the ordering.
func EqualSets(s1, s2 []string) bool {
	clone1 := slices.Clone(s1)
	clone2 := slices.Clone(s2)
	slices.Sort(clone1)
	slices.Sort(clone2)
	return slices.Equal(clone1, clone2)
}

// Subset checks if all elements of s1 are contained in s2. An empty s1 is always a subset of s2.
func Subset(s1, s2 []string) bool {
	for _, s1v := range s1 {
		if !slices.Contains(s2, s1v) {
			return false
		}
	}
	return true
}

// MatchLabels checks if all m2 keys and values are present in m1. If m1 or m2 is nil returns false.
func MatchLabels(m1, m2 map[string]string) bool {
	if m1 == nil || m2 == nil {
		return false
	}

	for k, v := range m2 {
		if m1[k] != v {
			return false
		}
	}

	return true
}

// ExceedFilePermissions returns true if any of the user, group or other permissions
// exceed their counterparts in what is passed as max permissions.
//
// Examples where filePermissions do not exceed filePermissionsMax:
//
//	filePermissions = "0003" filePermissionsMax = "0644"
//	filePermissions = "0444" filePermissionsMax = "0644"
//	filePermissions = "0600" filePermissionsMax = "0644"
//	filePermissions = "0644" filePermissionsMax = "0644"
//
// Examples where filePermissions exceed filePermissionsMax:
//
//	filePermissions = "0005" filePermissionsMax = "0644"
//	filePermissions = "0050" filePermissionsMax = "0644"
//	filePermissions = "0700" filePermissionsMax = "0644"
//	filePermissions = "0755" filePermissionsMax = "0644"
func ExceedFilePermissions(filePermissions, filePermissionsMax string) (bool, error) {
	filePermissionsInt, err := strconv.ParseInt(filePermissions, 8, 32)
	if err != nil {
		return false, err
	}
	filePermissionsMaxInt, err := strconv.ParseInt(filePermissionsMax, 8, 32)
	if err != nil {
		return false, err
	}

	fileModePermission := os.FileMode(filePermissionsInt)
	fileModePermissionsMax := os.FileMode(filePermissionsMaxInt)
	return fileModePermission&^fileModePermissionsMax != 0, nil
}

// MatchFilePermissionsAndOwnersCases returns []rule.CheckResult for a given file and its permissions and owners  for a select expected values.
func MatchFilePermissionsAndOwnersCases(
	filePermissions,
	fileOwnerUser,
	fileOwnerGroup,
	fileName string,
	expectedFilePermissionsMax string,
	expectedFileOwnerUsers,
	expectedFileOwnerGroups []string,
	target rule.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	if len(expectedFilePermissionsMax) > 0 {
		exceedFilePermissions, err := ExceedFilePermissions(filePermissions, expectedFilePermissionsMax)
		if err != nil {
			return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}
		}

		if exceedFilePermissions {
			detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileName, filePermissions, expectedFilePermissionsMax))
			checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
		}
	}

	if len(expectedFileOwnerUsers) > 0 {
		ok := false
		for _, expectedFileOwnerUser := range expectedFileOwnerUsers {
			if fileOwnerUser == expectedFileOwnerUser {
				ok = true
				break
			}
		}

		if !ok {
			detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerUser: %s, expectedOwnerUsers: %v", fileName, fileOwnerUser, expectedFileOwnerUsers))
			checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner user", detailedTarget))
		}
	}

	if len(expectedFileOwnerGroups) > 0 {
		ok := false
		for _, expectedFileOwnerGroup := range expectedFileOwnerGroups {
			if fileOwnerGroup == expectedFileOwnerGroup {
				ok = true
				break
			}
		}

		if !ok {
			detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerGroup: %s, expectedOwnerGroups: %v", fileName, fileOwnerGroup, expectedFileOwnerGroups))
			checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner group", detailedTarget))
		}
	}

	if len(checkResults) == 0 {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s, ownerUser: %s, ownerGroup: %s", fileName, filePermissions, fileOwnerUser, fileOwnerGroup))
		checkResults = append(checkResults, rule.PassedCheckResult("File has expected permissions and expected owner", detailedTarget))
	}

	return checkResults
}

// GetNodesAllocatablePodsNum return the number of free
// allocatable spots of pods for all nodes.
func GetNodesAllocatablePodsNum(pods []corev1.Pod, nodes []corev1.Node) map[string]int {
	nodesAllocatablePods := map[string]int{}

	for _, node := range nodes {
		nodesAllocatablePods[node.Name] = int(node.Status.Allocatable.Pods().Value())
	}
	for _, pod := range pods {
		if pod.Spec.NodeName != "" {
			nodesAllocatablePods[pod.Spec.NodeName]--
		}
	}

	return nodesAllocatablePods
}

// SelectPodOfReferenceGroup returns a single pod per owner reference group
// as well as groups the returned pods by the nodes they are scheduled on.
// Pods that do not have an owner reference will always be selected.
// Pods will not be grouped to nodes, which have reached their allocation limit.
// It tries to pick the pods in a way that fewer nodes will be selected.
func SelectPodOfReferenceGroup(pods []corev1.Pod, nodesAllocatablePods map[string]int, target rule.Target) (map[string][]corev1.Pod, []rule.CheckResult) {
	checkResults := []rule.CheckResult{}
	groupedPodsByNodes := map[string][]corev1.Pod{}
	groupedPodsByReferences := map[string][]corev1.Pod{}

	for _, pod := range pods {
		podTarget := target.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")

		if pod.Spec.NodeName != "" {
			if len(pod.OwnerReferences) == 0 {
				if nodesAllocatablePods[pod.Spec.NodeName] > 0 {
					groupedPodsByNodes[pod.Spec.NodeName] = append(groupedPodsByNodes[pod.Spec.NodeName], pod)
					continue
				}
				checkResults = append(checkResults, rule.WarningCheckResult("Pod cannot be tested since it is scheduled on a fully allocated node.", podTarget.With("node", pod.Spec.NodeName)))
				continue
			}

			ownerReferenceUID := fmt.Sprintf("%s-%s", pod.OwnerReferences[0].Name, string((pod.OwnerReferences[0].UID)))
			groupedPodsByReferences[ownerReferenceUID] = append(groupedPodsByReferences[ownerReferenceUID], pod)
			continue
		}

		checkResults = append(checkResults, rule.WarningCheckResult("Pod not (yet) scheduled", podTarget))
	}

	keys := make([]string, 0, len(groupedPodsByReferences))
	for key := range groupedPodsByReferences {
		keys = append(keys, key)
	}
	// sort reference keys by number of pods to minimize groups
	slices.SortFunc(keys, func(i, j string) int {
		return cmp.Compare(len(groupedPodsByReferences[i]), len(groupedPodsByReferences[j]))
	})

	for _, key := range keys {
		// we start from the smaller ref group because of fewer options to chose nodes from
		pods := groupedPodsByReferences[key]

		podOnUsedNodeIdx := slices.IndexFunc(pods, func(pod corev1.Pod) bool {
			_, ok := groupedPodsByNodes[pod.Spec.NodeName]
			return ok
		})

		// if there is a pod of the reference group which is scheduled on a selected node
		// then add this pod to the "to-be-checked" pods
		if podOnUsedNodeIdx >= 0 {
			pod := pods[podOnUsedNodeIdx]
			groupedPodsByNodes[pod.Spec.NodeName] = append(groupedPodsByNodes[pod.Spec.NodeName], pod)
			continue
		}

		// if none of the pods match already selected node then
		// select the node and add a single pod of the reference group for checking.
		// the selected node must have allocatable pod space
		maxAllocatablePods := 0
		podToUse := corev1.Pod{}
		for _, pod := range pods {
			nodeName := pod.Spec.NodeName
			if nodesAllocatablePods[nodeName] > maxAllocatablePods {
				maxAllocatablePods = nodesAllocatablePods[nodeName]
				podToUse = pod
			}
		}

		if maxAllocatablePods <= 0 {
			referenceGroupTarget := target.With("name", pods[0].OwnerReferences[0].Name, "uid", string((pods[0].OwnerReferences[0].UID)), "kind", "referenceGroup")
			checkResults = append(
				checkResults,
				rule.WarningCheckResult("Reference group cannot be tested since all pods of the group are scheduled on a fully allocated node.", referenceGroupTarget),
			)
			continue
		}

		groupedPodsByNodes[podToUse.Spec.NodeName] = []corev1.Pod{podToUse}
	}
	return groupedPodsByNodes, checkResults
}
