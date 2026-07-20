// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"maps"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubernetespod "github.com/gardener/diki/pkg/kubernetes/pod"
)

const (
	// PodContextWaitInterval is the interval between pod status polls.
	PodContextWaitInterval = 2 * time.Second
	// PodContextWaitTimeout is the maximum time to wait for the test pod to reach Running.
	// Both containers start immediately, so we only need enough time for image pull + scheduling.
	PodContextWaitTimeout = 1 * time.Minute

	// TestContainerName is the name of the container running the gardenlinux/tests suite.
	TestContainerName = "gardenlinux-test"
	// ReaderContainerName is the name of the container from which diki execs to read the completed report.
	// TODO (georgibaltiev): change the name of this container once https://github.com/gardener/diki/issues/771 has been addressed.
	// The container name coincides with the targeted container in the SimplePodExecutor.
	ReaderContainerName = "container"

	// ReportVolumeName is the name of the shared volume holding the JUnit report.
	ReportVolumeName = "test-report"
	// ReportMountPath is the in-pod path of the shared report volume.
	ReportMountPath = "/tests/tests/output"
	// ReportFilename is the name of the generated JUnit XML report inside the pod.
	ReportFilename = "report.xml"
	// ReportSizeLimitKi is the size limit of the report volume in kibibytes.
	ReportSizeLimitKi = 500

	// LabelComplianceRoleGardenlinuxTestPod is used as the label value for LabelComplianceRoleKey indicating gardenlinux test pods.
	LabelComplianceRoleGardenlinuxTestPod = "gardenlinux-test-pod"
)

// NewPodContext creates a new pod.PodContext tuned for the long-running gardenlinux/tests container.
func NewPodContext(c client.Client, config *rest.Config, additionalPodLabels map[string]string) (*kubernetespod.SimplePodContext, error) {
	podContext, err := kubernetespod.NewSimplePodContext(c, config, additionalPodLabels)
	if err != nil {
		return nil, err
	}
	podContext.WaitInterval = PodContextWaitInterval
	podContext.WaitTimeout = PodContextWaitTimeout
	return podContext, nil
}

// NewTestPod creates a new gardenlinux-test Pod.
func NewTestPod(name, namespace, gardenlinuxTestImage, reportReaderImage, nodeName string, additionalLabels map[string]string) func() *corev1.Pod {
	if len(name) > kubernetespod.MaxPodNameLength {
		name = name[:kubernetespod.MaxPodNameLength]
	}

	labels := map[string]string{}
	if additionalLabels != nil {
		labels = maps.Clone(additionalLabels)
	}

	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			ActiveDeadlineSeconds:        ptr.To[int64](300),
			AutomountServiceAccountToken: ptr.To(false),
			SecurityContext: &corev1.PodSecurityContext{
				// The FSGroup ensures that the written XML report is group-owned by 65532 - the reader will be able to get the report even if the "other" permission bits are dropped by the testing framework in a future release.
				FSGroup: ptr.To(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{
				{
					Name:  TestContainerName,
					Image: gardenlinuxTestImage,
					// The gardenlinux testing container requires certain privileged access, as described in the official documentation - https://github.com/gardenlinux/gardenlinux/tree/main/tests#gardener--kubernetes-cluster-live-tests
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
						"output/report.xml",
						"--system-booted",
						"--expected-users",
						"gardener",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      ReportVolumeName,
							MountPath: ReportMountPath,
						},
					},
				},
				{
					Name:  ReaderContainerName,
					Image: reportReaderImage,
					Command: []string{
						"/bin/busybox",
					},
					Args: []string{
						"sleep",
						"60",
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
							Name:      ReportVolumeName,
							MountPath: ReportMountPath,
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
					Name: ReportVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							SizeLimit: resource.NewScaledQuantity(ReportSizeLimitKi, resource.Kilo),
						},
					},
				},
			},
		},
	}

	if nodeName != "" {
		testPod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": nodeName}
	}

	// Labels that will always be applied to the pod and cannot be overwritten
	testPod.Labels[kubernetespod.LabelComplianceRoleKey] = LabelComplianceRoleGardenlinuxTestPod

	return func() *corev1.Pod {
		return testPod
	}
}
