// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	// LabelInstanceID is used to group all pods created by a single ruleset.
	LabelInstanceID = "compliance.gardener.cloud/instanceID"

	// LabelComplianceRoleKey is used to label pods related to compliance operations in the cluster.
	LabelComplianceRoleKey = "compliance.gardener.cloud/role"

	// LabelComplianceRolePrivPod is used as the label value for LabelComplianceRoleKey indicating privileged diki pods.
	LabelComplianceRolePrivPod = "diki-privileged-pod"

	maxNameLength = 63
)

// NewPrivilegedPod creates a new privileged Pod.
func NewPrivilegedPod(name, namespace, image, nodeName string, additionalLabels map[string]string) func() *corev1.Pod {
	if len(name) > maxNameLength {
		name = name[:maxNameLength]
	}

	labels := map[string]string{}
	if additionalLabels != nil {
		labels = maps.Clone(additionalLabels)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "container",
					Image:   image,
					Command: []string{"chroot", "/host", "/bin/bash", "-c", "nsenter -m -t $(pgrep -xo systemd) sleep 600"},
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root-volume",
							MountPath: "/host",
							ReadOnly:  false,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root-volume",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			HostNetwork:   true,
			HostPID:       true,
			RestartPolicy: "Never",
			Tolerations: []corev1.Toleration{
				{
					Effect:   "NoSchedule",
					Operator: "Exists",
				},
				{
					Effect:   "NoExecute",
					Operator: "Exists",
				},
			},
		},
	}

	if nodeName != "" {
		pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": nodeName}
	}

	// Labels that will always be applied to the pod and cannot be overwritten
	pod.Labels[LabelComplianceRoleKey] = LabelComplianceRolePrivPod

	return func() *corev1.Pod {
		return pod
	}
}
