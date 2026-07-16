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

		It("should construct a pod with the given name, namespace and node selector", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Name).To(Equal("my-pod"))
			Expect(p.Namespace).To(Equal(gardenlinuxpod.SystemNamespace))
			Expect(p.Spec.NodeSelector).To(Equal(map[string]string{"kubernetes.io/hostname": nodeName}))
		})

		It("should truncate names longer than MaxPodNameLength", func() {
			longName := strings.Repeat("a", kubernetespod.MaxPodNameLength+10)

			p := gardenlinuxpod.NewTestPod(longName, testImage, sidecarImage, nodeName, nil)()

			Expect(p.Name).To(HaveLen(kubernetespod.MaxPodNameLength))
			Expect(p.Name).To(Equal(strings.Repeat("a", kubernetespod.MaxPodNameLength)))
		})

		It("should not preserve names at or below MaxPodNameLength", func() {
			name := strings.Repeat("b", kubernetespod.MaxPodNameLength)

			p := gardenlinuxpod.NewTestPod(name, testImage, sidecarImage, nodeName, nil)()

			Expect(p.Name).To(Equal(name))
		})

		It("should omit the node selector when nodeName is empty", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, "", nil)()

			Expect(p.Spec.NodeSelector).To(BeNil())
		})

		It("should merge additional labels and always set the compliance role label", func() {
			extra := map[string]string{
				"foo":     "bar",
				"example": "value",
			}

			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, extra)()

			Expect(p.Labels).To(HaveKeyWithValue("foo", "bar"))
			Expect(p.Labels).To(HaveKeyWithValue("example", "value"))
			Expect(p.Labels).To(HaveKeyWithValue(kubernetespod.LabelComplianceRoleKey, gardenlinuxpod.LabelComplianceRoleGardenlinuxTestPod))
		})

		It("should overwrite an attempt to set the compliance role label from additionalLabels", func() {
			extra := map[string]string{
				kubernetespod.LabelComplianceRoleKey: "attacker-value",
			}

			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, extra)()

			Expect(p.Labels).To(HaveKeyWithValue(kubernetespod.LabelComplianceRoleKey, gardenlinuxpod.LabelComplianceRoleGardenlinuxTestPod))
		})

		It("should not mutate the caller's additionalLabels map", func() {
			extra := map[string]string{"foo": "bar"}

			_ = gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, extra)()

			Expect(extra).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should set pod-level security defaults", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Spec.AutomountServiceAccountToken).To(Equal(ptr.To(false)))
			Expect(p.Spec.HostNetwork).To(BeTrue())
			Expect(p.Spec.HostPID).To(BeTrue())
			Expect(p.Spec.HostIPC).To(BeFalse())
			Expect(p.Spec.RestartPolicy).To(Equal(corev1.RestartPolicyNever))
			Expect(p.Spec.SecurityContext).NotTo(BeNil())
			Expect(p.Spec.SecurityContext.FSGroup).To(Equal(ptr.To(int64(65532))))
			Expect(p.Spec.SecurityContext.SeccompProfile).NotTo(BeNil())
			Expect(p.Spec.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
		})

		It("should tolerate all NoSchedule and NoExecute taints", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Spec.Tolerations).To(ConsistOf(
				corev1.Toleration{Effect: corev1.TaintEffectNoSchedule, Operator: corev1.TolerationOpExists},
				corev1.Toleration{Effect: corev1.TaintEffectNoExecute, Operator: corev1.TolerationOpExists},
			))
		})

		It("should configure the privileged test container with the test image", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Spec.InitContainers).To(BeEmpty())
			Expect(p.Spec.Containers).To(HaveLen(2))
			tc := p.Spec.Containers[0]
			Expect(tc.Name).To(Equal("gardenlinux-test"))
			Expect(tc.Image).To(Equal(testImage))
			Expect(tc.SecurityContext).NotTo(BeNil())
			Expect(tc.SecurityContext.Privileged).To(Equal(ptr.To(true)))
			Expect(tc.Command).To(BeEmpty())
			Expect(tc.Args).To(Equal([]string{
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
			}))
			Expect(tc.VolumeMounts).To(ConsistOf(corev1.VolumeMount{
				Name:      gardenlinuxpod.ReportVolumeName,
				MountPath: gardenlinuxpod.ReportMountPath,
			}))
		})

		It("should configure the reader container", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Spec.Containers).To(HaveLen(2))
			rc := p.Spec.Containers[1]
			Expect(rc.Name).To(Equal("container"))
			Expect(rc.Image).To(Equal(sidecarImage))
			Expect(rc.Command).To(Equal([]string{
				"/bin/busybox",
			}))
			Expect(rc.Args).To(Equal([]string{
				"sleep",
				"900",
			}))

			Expect(rc.SecurityContext).NotTo(BeNil())
			Expect(rc.SecurityContext.Privileged).To(Equal(ptr.To(false)))
			Expect(rc.SecurityContext.AllowPrivilegeEscalation).To(Equal(ptr.To(false)))
			Expect(rc.SecurityContext.RunAsNonRoot).To(Equal(ptr.To(true)))
			Expect(rc.SecurityContext.RunAsUser).To(Equal(ptr.To(int64(65532))))
			Expect(rc.SecurityContext.RunAsGroup).To(Equal(ptr.To(int64(65532))))
			Expect(rc.SecurityContext.ReadOnlyRootFilesystem).To(Equal(ptr.To(true)))
			Expect(rc.SecurityContext.Capabilities.Drop).To(Equal([]corev1.Capability{"ALL"}))

			Expect(rc.VolumeMounts).To(ConsistOf(
				corev1.VolumeMount{
					Name:      gardenlinuxpod.ReportVolumeName,
					MountPath: gardenlinuxpod.ReportMountPath,
					ReadOnly:  true,
				},
			))
		})

		It("should declare a bounded emptyDir volume for the JUnit report", func() {
			p := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)()

			Expect(p.Spec.Volumes).To(HaveLen(1))

			var reportVolume corev1.Volume
			for _, v := range p.Spec.Volumes {
				if v.Name == gardenlinuxpod.ReportVolumeName {
					reportVolume = v
				}
			}

			Expect(reportVolume.EmptyDir).NotTo(BeNil())
			Expect(reportVolume.EmptyDir.SizeLimit).NotTo(BeNil())
			Expect(reportVolume.EmptyDir.SizeLimit.Equal(*resource.NewScaledQuantity(gardenlinuxpod.ReportSizeLimitKi, resource.Kilo))).To(BeTrue())
		})

		It("should return the same pod instance on repeated constructor invocations", func() {
			ctor := gardenlinuxpod.NewTestPod("my-pod", testImage, sidecarImage, nodeName, nil)

			Expect(ctor()).To(BeIdenticalTo(ctor()))
		})
	})
})
