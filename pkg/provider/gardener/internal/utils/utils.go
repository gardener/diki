// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"fmt"
	"slices"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dikiutils "github.com/gardener/diki/pkg/internal/utils"
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

// MatchFileOwnersCases returns []rule.CheckResult for a given file and its owners for a select expected values.
func MatchFileOwnersCases(
	fileOwnerUser,
	fileOwnerGroup,
	fileName string,
	expectedFileOwnerUsers,
	expectedFileOwnerGroups []string,
	target rule.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}

	if !slices.Contains(expectedFileOwnerUsers, fileOwnerUser) {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerUser: %s, expectedOwnerUsers: %v", fileName, fileOwnerUser, expectedFileOwnerUsers))
		checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner user", detailedTarget))
	}

	if !slices.Contains(expectedFileOwnerGroups, fileOwnerGroup) {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerGroup: %s, expectedOwnerGroups: %v", fileName, fileOwnerGroup, expectedFileOwnerGroups))
		checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner group", detailedTarget))
	}

	if len(checkResults) == 0 {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerUser: %s, ownerGroup: %s", fileName, fileOwnerUser, fileOwnerGroup))
		checkResults = append(checkResults, rule.PassedCheckResult("File has expected owners", detailedTarget))
	}

	return checkResults
}

// MatchFilePermissionsAndOwnersCases returns []rule.CheckResult for a given file and its permissions and owners for a select expected values.
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
		exceedFilePermissions, err := dikiutils.ExceedFilePermissions(filePermissions, expectedFilePermissionsMax)
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
