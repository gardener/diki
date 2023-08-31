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
	"strings"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

// ReadyNode contains a single Node and whether it is in Ready state or not
type ReadyNode struct {
	Node  *corev1.Node
	Ready bool
}

// GetObjectsMetadata returns the object metadata for all resources of a given group version kind for a namespace,
// or all namespaces if it's set to "".
// It retrieves objects by portions set by limit.
func GetObjectsMetadata(ctx context.Context, c client.Client, gvk schema.GroupVersionKind, namespace string, selector labels.Selector, limit int64) ([]metav1.PartialObjectMetadata, error) {
	objectList := &metav1.PartialObjectMetadataList{}
	objectList.SetGroupVersionKind(gvk)
	objects := []metav1.PartialObjectMetadata{}

	for {
		if err := c.List(ctx, objectList, client.InNamespace(namespace), client.Limit(limit), client.MatchingLabelsSelector{Selector: selector}, client.Continue(objectList.Continue)); err != nil {
			return nil, err
		}

		objects = append(objects, objectList.Items...)

		if len(objectList.Continue) == 0 {
			return objects, nil
		}
	}
}

// GetAllPods return all pods for a given namespace, or all namespaces if it's set to empty string "".
// It retrieves pods by portions set by limit.
func GetAllPods(ctx context.Context, c client.Client, namespace string, selector labels.Selector, limit int64) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	pods := []corev1.Pod{}

	for {
		if err := c.List(ctx, podList, client.InNamespace(namespace), client.Limit(limit), client.MatchingLabelsSelector{Selector: selector}, client.Continue(podList.Continue)); err != nil {
			return nil, err
		}

		pods = append(pods, podList.Items...)

		if len(podList.Continue) == 0 {
			return pods, nil
		}
	}
}

// GetNodes return all nodes. It retrieves pods by portions set by limit.
func GetNodes(ctx context.Context, c client.Client, limit int64) ([]corev1.Node, error) {
	nodeList := &corev1.NodeList{}
	nodes := []corev1.Node{}

	for {
		if err := c.List(ctx, nodeList, client.Limit(limit), client.Continue(nodeList.Continue)); err != nil {
			return nil, err
		}

		nodes = append(nodes, nodeList.Items...)

		if len(nodeList.Continue) == 0 {
			return nodes, nil
		}
	}
}

// GetWorkers return all workers for a given namespace, or all namespaces if it's set to empty string "".
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

// GetPodSecurityPolicies returns all pod security policies.
// It retrieves policies by portions set by limit.
func GetPodSecurityPolicies(ctx context.Context, c client.Client, limit int64) ([]policyv1beta1.PodSecurityPolicy, error) {
	podSecurityPoliciesList := &policyv1beta1.PodSecurityPolicyList{}
	podSecurityPolicies := []policyv1beta1.PodSecurityPolicy{}

	for {
		if err := c.List(ctx, podSecurityPoliciesList, client.Limit(limit), client.Continue(podSecurityPoliciesList.Continue)); err != nil {
			return nil, err
		}

		podSecurityPolicies = append(podSecurityPolicies, podSecurityPoliciesList.Items...)

		if len(podSecurityPoliciesList.Continue) == 0 {
			return podSecurityPolicies, nil
		}
	}
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
				if node.ObjectMeta.Labels[v1beta1constants.LabelWorkerPool] == workerGroup.Name && NodeReadyStatus(node) {
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

// NodeReadyStatus returns true if the given node has NodeReady status condition true and false in every other case.
func NodeReadyStatus(node corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// GetContainerFromDeployment returns a container object with a specific cainerName, if such container is not present it retuns found=false
func GetContainerFromDeployment(deployment *appsv1.Deployment, containerName string) (container corev1.Container, found bool) {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container, true
		}
	}
	return corev1.Container{}, false
}

// GetContainerFromStatefulSet returns a container object with a specific cainerName, if such container is not present it retuns found=false
func GetContainerFromStatefulSet(statefulSet *appsv1.StatefulSet, containerName string) (container corev1.Container, found bool) {
	for _, container := range statefulSet.Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container, true
		}
	}
	return corev1.Container{}, false
}

// GetVolumeFromDeployment returns a volume object with a specific volumeName, if such volume is not present it retuns found=false
func GetVolumeFromDeployment(deployment *appsv1.Deployment, volumeName string) (volume corev1.Volume, found bool) {
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == volumeName {
			return volume, true
		}
	}
	return corev1.Volume{}, false
}

// GetVolumeFromStatefulSet returns a volume object with a specific volumeName, if such volume is not present it retuns found=false
func GetVolumeFromStatefulSet(statefulSet *appsv1.StatefulSet, volumeName string) (volume corev1.Volume, found bool) {
	for _, volume := range statefulSet.Spec.Template.Spec.Volumes {
		if volume.Name == volumeName {
			return volume, true
		}
	}
	return corev1.Volume{}, false
}

// FindFlagValueRaw returns the value of a specific flag in a commands slice.
// The following flag representations are supported:
//
//	--flag=foo
//	--flag foo
//	--flag
//	-flag=foo
//	-flag foo
//	-flag
//
// Notable ambiguous behavior:
//
//	--flag="foo"           -> `"foo"`
//	--flag=foo --flag2=bar -> "foo --flag2=bar"
//	--flag=   foo          -> "foo"
//	--flag=                -> ""
func FindFlagValueRaw(command []string, flag string) []string {
	flag = fmt.Sprintf("-%s", flag)

	result := []string{}
	for _, c := range command {
		before, after, found := strings.Cut(c, flag)
		if found && (before == "" || before == "-") && (len(after) == 0 || string(after[0]) == "=" || string(after[0]) == " ") {
			if len(after) != 0 && string(after[0]) == "=" {
				after = after[1:]
			}
			result = append(result, strings.TrimSpace(after))
		}
	}

	return result
}

// FindInnerValue returns the value of a specific flag when the format is
// flag1=value1,flag3=value3,flag3=value3
func FindInnerValue(values []string, flag string) []string {
	result := []string{}
	flag = fmt.Sprintf("%s=", flag)
	for _, value := range values {
		v := value
		for {
			_, after, found := strings.Cut(v, flag)
			if !found {
				break
			}
			var before string
			before, v, _ = strings.Cut(after, ",")
			result = append(result, before)
		}
	}
	return result
}

// GetFileDataFromVolume returns byte slice of the value of a specific Data field
// in a ConfigMap or Secret volume
func GetFileDataFromVolume(ctx context.Context, c client.Client, namespace string, volume corev1.Volume, fileName string) ([]byte, error) {
	if volume.ConfigMap != nil {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      volume.ConfigMap.Name,
				Namespace: namespace,
			},
		}
		err := c.Get(ctx, client.ObjectKeyFromObject(configMap), configMap)
		if err != nil {
			return nil, err
		}

		_, ok := configMap.Data[fileName]
		if !ok {
			return nil, fmt.Errorf("configMap: %s does not contain filed: %s in Data field", volume.ConfigMap.Name, fileName)
		}
		return []byte(configMap.Data[fileName]), nil
	}

	if volume.Secret != nil {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      volume.Secret.SecretName,
				Namespace: namespace,
			},
		}
		err := c.Get(ctx, client.ObjectKeyFromObject(secret), secret)
		if err != nil {
			return nil, err
		}

		_, ok := secret.Data[fileName]
		if !ok {
			return nil, fmt.Errorf("secret: %s does not contain filed: %s in Data field", volume.Secret.SecretName, fileName)
		}
		return secret.Data[fileName], nil
	}

	return nil, fmt.Errorf("cannot handle volume: %v", volume)
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
		filePermissionsInt, err := strconv.ParseInt(filePermissions, 8, 32)
		if err != nil {
			return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}
		}
		expectedFilePermissionsMaxInt, err := strconv.ParseInt(expectedFilePermissionsMax, 8, 32)
		if err != nil {
			return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}
		}

		fileModePermission := os.FileMode(filePermissionsInt)
		expectedFileModePermissionsMax := os.FileMode(expectedFilePermissionsMaxInt)

		if fileModePermission > expectedFileModePermissionsMax {
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
