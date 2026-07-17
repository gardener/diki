// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	kubernetespod "github.com/gardener/diki/pkg/kubernetes/pod"
	gardenlinuxpod "github.com/gardener/diki/pkg/provider/managedk8s/ruleset/gardenlinux/pod"
)

var _ = Describe("pod", func() {
	Describe("#NewPodContext", func() {
		var (
			fakeClient client.Client
			fakeConfig *rest.Config
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			fakeConfig = &rest.Config{Host: "foo"}
		})

		It("should create a pod context with gardenlinux-tuned wait interval and timeout", func() {
			ctx, err := gardenlinuxpod.NewPodContext(fakeClient, fakeConfig, map[string]string{})

			Expect(err).To(BeNil())
			Expect(ctx.WaitInterval).To(Equal(gardenlinuxpod.PodContextWaitInterval))
			Expect(ctx.WaitTimeout).To(Equal(gardenlinuxpod.PodContextWaitTimeout))
		})
	})

	Describe("#NewTestPod", func() {
		const (
			testImage    = "test:v0.0.0"
			sidecarImage = "sidecar:v0.0.0"
			nodeName     = "worker-1"
		)

		expectedPod := func() *corev1.Pod {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pod",
					Namespace: "kube-system",
					Labels: map[string]string{
						kubernetespod.LabelComplianceRoleKey: "gardenlinux-test-pod",
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: ptr.To(false),
					NodeSelector:                 map[string]string{"kubernetes.io/hostname": nodeName},
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup: ptr.To(int64(65532)),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  gardenlinuxpod.TestContainerName,
							Image: testImage,
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
							},
							Args: []string{
								"./run_tests",
								"integration/security/compliance",
								"-v",
								"-m",
								"security_id",
								"--junit-xml",
								"output/test.xml",
								"--system-booted",
								"--expected-users",
								"gardener",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "test-report",
									MountPath: "/tests/tests/output",
								},
							},
						},
						{
							Name:  gardenlinuxpod.ReaderContainerName,
							Image: sidecarImage,
							Command: []string{
								"/bin/busybox",
							},
							Args: []string{
								"sleep",
								"900",
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged:               ptr.To(false),
								AllowPrivilegeEscalation: ptr.To(false),
								RunAsNonRoot:             ptr.To(true),
								RunAsUser:                ptr.To(int64(65532)),
								RunAsGroup:               ptr.To(int64(65532)),
								ReadOnlyRootFilesystem:   ptr.To(true),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "test-report",
									MountPath: "/tests/tests/output",
									ReadOnly:  true,
								},
							},
						},
					},
					HostPID:       true,
					RestartPolicy: corev1.RestartPolicyNever,
					Tolerations: []corev1.Toleration{
						{
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect:   corev1.TaintEffectNoExecute,
							Operator: corev1.TolerationOpExists,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: gardenlinuxpod.ReportVolumeName,
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: resource.NewScaledQuantity(gardenlinuxpod.ReportSizeLimitKi, resource.Kilo),
								},
							},
						},
					},
				},
			}
		}

		It("should construct the canonical pod spec", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, nodeName, nil)()

			Expect(p).To(Equal(expectedPod()))
		})

		It("should truncate names longer than MaxPodNameLength", func() {
			longName := strings.Repeat("a", kubernetespod.MaxPodNameLength+10)

			p := gardenlinuxpod.NewTestPod(longName, "kube-system", testImage, sidecarImage, nodeName, nil)()

			expected := expectedPod()
			expected.Name = strings.Repeat("a", kubernetespod.MaxPodNameLength)
			Expect(p).To(Equal(expected))
		})

		It("should not truncate names at or below MaxPodNameLength", func() {
			name := strings.Repeat("b", kubernetespod.MaxPodNameLength)

			p := gardenlinuxpod.NewTestPod(name, "kube-system", testImage, sidecarImage, nodeName, nil)()

			expected := expectedPod()
			expected.Name = name
			Expect(p).To(Equal(expected))
		})

		It("should omit the node selector when nodeName is empty", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, "", nil)()

			expected := expectedPod()
			expected.Spec.NodeSelector = nil
			Expect(p).To(Equal(expected))
		})

		It("should merge additional labels and always set the compliance role label", func() {
			extra := map[string]string{
				"foo":     "bar",
				"example": "value",
			}

			p := gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, nodeName, extra)()

			expected := expectedPod()
			expected.Labels["foo"] = "bar"
			expected.Labels["example"] = "value"
			Expect(p).To(Equal(expected))
		})

		It("should overwrite an attempt to set the compliance role label from additionalLabels", func() {
			extra := map[string]string{
				kubernetespod.LabelComplianceRoleKey: "attacker-value",
			}

			p := gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, nodeName, extra)()

			Expect(p).To(Equal(expectedPod()))
		})

		It("should not mutate the caller's additionalLabels map", func() {
			extra := map[string]string{"foo": "bar"}

			_ = gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, nodeName, extra)()

			Expect(extra).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should return the same pod instance on repeated constructor invocations", func() {
			ctor := gardenlinuxpod.NewTestPod("my-pod", "kube-system", testImage, sidecarImage, nodeName, nil)

			Expect(ctor()).To(BeIdenticalTo(ctor()))
		})
	})
})
