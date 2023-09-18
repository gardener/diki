// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
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
	"github.com/gardener/diki/pkg/provider/gardener"
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

// CheckFilePermissions returns true if the given filePermissions do not exceed filePermissionsMax.
func CheckFilePermissions(filePermissions, filePermissionsMax string) (bool, error) {
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
	return fileModePermission&^fileModePermissionsMax == 0, nil
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
	target gardener.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	if len(expectedFilePermissionsMax) > 0 {
		areFilePermissionsCompliant, err := CheckFilePermissions(filePermissions, expectedFilePermissionsMax)
		if err != nil {
			return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}
		}

		if !areFilePermissionsCompliant {
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
