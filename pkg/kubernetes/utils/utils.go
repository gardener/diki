// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/kubernetes/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/rule"
)

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

// GetPods returns all pods for a given namespace, or all namespaces if it's set to empty string "".
// It retrieves pods by portions set by limit.
func GetPods(ctx context.Context, c client.Client, namespace string, selector labels.Selector, limit int64) ([]corev1.Pod, error) {
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

// GetReplicaSets returns all replicaSets for a given namespace, or all namespaces if it's set to empty string "".
// It retrieves replicaSets by portions set by limit.
func GetReplicaSets(ctx context.Context, c client.Client, namespace string, selector labels.Selector, limit int64) ([]appsv1.ReplicaSet, error) {
	replicaSetList := &appsv1.ReplicaSetList{}
	replicaSets := []appsv1.ReplicaSet{}

	for {
		if err := c.List(ctx, replicaSetList, client.InNamespace(namespace), client.Limit(limit), client.MatchingLabelsSelector{Selector: selector}, client.Continue(replicaSetList.Continue)); err != nil {
			return nil, err
		}

		replicaSets = append(replicaSets, replicaSetList.Items...)

		if len(replicaSetList.Continue) == 0 {
			return replicaSets, nil
		}
	}
}

// GetDeploymentPods returns all pods of a given deployment.
func GetDeploymentPods(ctx context.Context, c client.Client, name, namespace string) ([]corev1.Pod, error) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return nil, err
	}

	allPods, err := GetPods(ctx, c, namespace, labels.NewSelector(), 300)
	if err != nil {
		return nil, err
	}

	replicaSets, err := GetReplicaSets(ctx, c, namespace, labels.NewSelector(), 300)
	if err != nil {
		return nil, err
	}

	pods := []corev1.Pod{}
	for _, replicaSet := range replicaSets {
		// When not specified replicaSet.Spec.Replicas defaults to 1: https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/#replicas
		ownerRef := replicaSet.OwnerReferences[0]
		if ownerRef.UID == deployment.UID && ownerRef.Kind == "Deployment" && (replicaSet.Spec.Replicas == nil || *replicaSet.Spec.Replicas > 0) {
			for _, pod := range allPods {
				if pod.OwnerReferences[0].UID == replicaSet.UID {
					pods = append(pods, pod)
				}
			}
		}
	}

	return pods, nil
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

// GetNamespaces returns a map containing all namespaces, where the names of the namespaces are used as a keys.
func GetNamespaces(ctx context.Context, c client.Client) (map[string]corev1.Namespace, error) {
	namespaceList := &corev1.NamespaceList{}

	if err := c.List(ctx, namespaceList); err != nil {
		return nil, err
	}

	res := make(map[string]corev1.Namespace, len(namespaceList.Items))
	for _, n := range namespaceList.Items {
		res[n.Name] = n
	}
	return res, nil
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

// GetCommandOptionFromDeployment returns command and args from a specific deployment container.
func GetCommandOptionFromDeployment(ctx context.Context, c client.Client, deploymentName, containerName, namespace, option string) ([]string, error) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: namespace,
		},
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return []string{}, err
	}

	container, found := GetContainerFromDeployment(deployment, containerName)
	if !found {
		return []string{}, fmt.Errorf("deployment: %s does not contain container: %s", deploymentName, containerName)
	}

	optionSlice := FindFlagValueRaw(append(container.Command, container.Args...), option)

	return optionSlice, nil
}

// GetKubeletCommand returns the used kubelet command
func GetKubeletCommand(ctx context.Context, podExecutor pod.PodExecutor) (string, error) {
	rawKubeletCommand, err := podExecutor.Execute(ctx, "bin/sh", `ps x -o command | grep "/opt/bin/kubelet" | grep -v "grep"`)
	if err != nil {
		return "", err
	}

	return rawKubeletCommand, nil
}

// IsFlagSet returns true if a specific flag is set in the command
func IsFlagSet(rawCommand, option string) bool {
	optionSlice := FindFlagValueRaw(strings.Split(rawCommand, " "), option)

	return len(optionSlice) != 0
}

// GetKubeletConfig returns the kubelet config specified in the kubelet command's option `--config`
func GetKubeletConfig(ctx context.Context, podExecutor pod.PodExecutor, rawKubeletCommand string) (*config.KubeletConfig, error) {
	configPathSlice := FindFlagValueRaw(strings.Split(rawKubeletCommand, " "), "config")

	if len(configPathSlice) == 0 {
		return &config.KubeletConfig{}, errors.New("kubelet config file has not been set")
	}
	if len(configPathSlice) > 1 {
		return &config.KubeletConfig{}, errors.New("kubelet config file has been set more than once")
	}
	configPath := configPathSlice[0]

	rawKubeletConfig, err := podExecutor.Execute(ctx, "bin/sh", fmt.Sprintf("cat %s", configPath))
	if err != nil {
		return &config.KubeletConfig{}, err
	}

	kubeletConfig := &config.KubeletConfig{}
	err = yaml.Unmarshal([]byte(rawKubeletConfig), kubeletConfig)
	if err != nil {
		return &config.KubeletConfig{}, err
	}

	return kubeletConfig, nil
}

// GetNodeConfigz returns the runtime kubelet config
func GetNodeConfigz(ctx context.Context, coreV1RESTClient rest.Interface, nodeName string) (*config.KubeletConfig, error) {
	request := coreV1RESTClient.Get().Resource("nodes").Name(nodeName).SubResource("proxy").Suffix("configz")
	rawNodeConfigz, err := request.DoRaw(ctx)
	if err != nil {
		return &config.KubeletConfig{}, err
	}

	nodeConfigz := &config.NodeConfigz{}
	err = json.Unmarshal(rawNodeConfigz, nodeConfigz)
	if err != nil {
		return &config.KubeletConfig{}, err
	}
	return &nodeConfigz.KubeletConfig, nil
}

// GetVolumeConfigByteSliceByMountPath returns the byte slice data of a specific volume in a deployment by the volumes mountPath and containerName
func GetVolumeConfigByteSliceByMountPath(ctx context.Context, c client.Client, deployment *appsv1.Deployment, containerName, mountPath string) ([]byte, error) {
	container, found := GetContainerFromDeployment(deployment, containerName)
	if !found {
		return nil, fmt.Errorf("deployment does not contain container with name: %s", containerName)
	}

	volumeMount, err := getVolumeMountFromContainerByPath(container, mountPath)
	if err != nil {
		return nil, err
	}
	fileName := strings.Replace(mountPath, fmt.Sprintf("%s/", volumeMount.MountPath), "", 1)

	volume, found := GetVolumeFromDeployment(deployment, volumeMount.Name)
	if !found {
		return nil, fmt.Errorf("deployment does not contain volume with name: %s", volumeMount.Name)
	}

	data, err := GetFileDataFromVolume(ctx, c, deployment.Namespace, volume, fileName)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// getVolumeMountFromContainerByPath returns the VolumeMount of a container with a given path. If the VolumeMount is not found an error is returned
func getVolumeMountFromContainerByPath(container corev1.Container, volumePath string) (corev1.VolumeMount, error) {
	volumeMounts := container.VolumeMounts
	sort.Slice(volumeMounts, func(i, j int) bool {
		return volumeMounts[i].MountPath < volumeMounts[j].MountPath
	})
	for _, volumeMount := range volumeMounts {
		if strings.HasPrefix(volumePath, volumeMount.MountPath) {
			return volumeMount, nil
		}
	}
	return corev1.VolumeMount{}, fmt.Errorf("cannot find volume with path %s", volumePath)
}

// RESTConfigFromFile builds a [*rest.Config] from a file.
func RESTConfigFromFile(filePath string) (*rest.Config, error) {
	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, err
	}
	config, err := clientcmd.RESTConfigFromKubeConfig(data)
	if err != nil {
		return nil, err
	}

	return config, nil
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

// SelectNodes returns a subset of nodes. Containing
// a single node per unique label value combination.
// Nodes that have reached their allocation limit will not be returned.
// If no labels are provided all allocatable nodes will be returned.
// If skipEmpty is set to `true` nodes that do not have any of the
// presented labels will not be returned.
func SelectNodes(nodes []corev1.Node, nodesAllocatablePods map[string]int, labels []string, skipEmpty bool) ([]corev1.Node, []rule.CheckResult) {
	selectedNodes := []corev1.Node{}
	checkResults := []rule.CheckResult{}

	// if not labels are provided return all allocatable nodes
	if len(labels) == 0 {
		for _, node := range nodes {
			if nodesAllocatablePods[node.Name] > 0 {
				selectedNodes = append(selectedNodes, node)
			}
		}
		return selectedNodes, checkResults
	}

	// map node by unique label values combination
	groupedNodes := map[string][]corev1.Node{}
	// character to seperate values in map keys
	// the selecter char is `+` since it cannot
	// be contained in a label's value
	delimiter := "+"

	for _, node := range nodes {
		var keyBuilder strings.Builder
		for _, label := range labels {
			if value, ok := node.Labels[label]; ok {
				keyBuilder.WriteString(value)
			} else if skipEmpty {
				keyBuilder.Reset()
				break
			}
			keyBuilder.WriteString(delimiter)
		}

		key := keyBuilder.String()
		if len(key) > 0 {
			groupedNodes[key] = append(groupedNodes[key], node)
		}
	}

	for key, currentNodes := range groupedNodes {
		idx := slices.IndexFunc(currentNodes, func(node corev1.Node) bool {
			return nodesAllocatablePods[node.Name] > 0
		})

		if idx < 0 {
			values := key
			var labelsBuilder strings.Builder
			for _, label := range labels {
				charIdx := strings.Index(values, delimiter)
				if charIdx != -1 {
					value := values[:charIdx]
					if len(value) == 0 {
						value = "\"\""
					}
					labelsBuilder.WriteString(fmt.Sprintf("%s: %s, ", label, value))
					values = values[charIdx+1:]
				}
			}

			labelMessage := labelsBuilder.String()
			labelMessage = labelMessage[:len(labelMessage)-2]
			checkResults = append(checkResults, rule.WarningCheckResult("No allocatable nodes of label value combination", rule.NewTarget("labels", labelMessage)))
			continue
		}

		selectedNodes = append(selectedNodes, currentNodes[idx])
	}

	return selectedNodes, checkResults
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
