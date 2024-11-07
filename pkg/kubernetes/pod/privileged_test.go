// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/gardener/diki/pkg/kubernetes/pod"
)

var _ = Describe("podutils", func() {
	Describe("#NewPrivilegedPod", func() {
		var (
			name        = "foo"
			namespace   = "bar"
			image       = "foo-bar:1"
			nodeName    = "node"
			expectedPod *corev1.Pod
		)

		BeforeEach(func() {
			expectedPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
					Labels: map[string]string{
						"compliance.gardener.cloud/role": "diki-privileged-pod",
						"one":                            "two",
					},
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
		})

		It("should return correct pod", func() {
			podFunc := pod.NewPrivilegedPod(name, namespace, image, "", nil)

			delete(expectedPod.Labels, "one")
			Expect(podFunc()).To(Equal(expectedPod))
		})

		It("should return correct pod when nodeName is specified", func() {
			expectedPod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": nodeName}
			podFunc := pod.NewPrivilegedPod(name, namespace, image, nodeName, map[string]string{"one": "two"})

			Expect(podFunc()).To(Equal(expectedPod))
		})

		It("should return correct pod when podName length is more than 63", func() {
			tooLongPodName := strings.Repeat("a", 256)
			expectedPod.ObjectMeta.Name = strings.Repeat("a", 63)
			podFunc := pod.NewPrivilegedPod(tooLongPodName, namespace, image, "", map[string]string{"one": "two"})

			Expect(podFunc()).To(Equal(expectedPod))
		})
	})
})
