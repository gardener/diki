// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"context"
	"errors"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#RuleNodeFiles", func() {
	const (
		rawKubeletCommand = `--config=/var/lib/kubelet/config/kubelet --kubeconfig=/var/lib/kubelet/kubeconfig-real`
		kubeletConfig     = `authentication:
  x509:
    clientCAFile: /var/lib/kubelet/ca.crt
`
		kubeletServicePath               = `/etc/systemd/system/kubelet.service`
		emptyFileStats                   = ``
		compliantCAFileStats             = `644 0 0 /var/lib/kubelet/ca.crt`
		compliantKubeconfigRealFileStats = `600 0 0 /var/lib/kubelet/kubeconfig-real`
		compliantKubeletFileStats        = `644 0 0 /var/lib/kubelet/config/kubelet`
		compliantKubeletServiceFileStats = `644 0 0 /etc/systemd/system/kubelet.service`
		compliantPKIAllFilesStats        = `755 0 0 /var/lib/kubelet/pki
600 0 0 /var/lib/kubelet/pki/key.key
644 0 0 /var/lib/kubelet/pki/crt.crt
600 0 0 /var/lib/kubelet/pki/kubelet-server-2023.pem`
		compliantPKIKeyFilesStats           = `600 0 0 /var/lib/kubelet/pki/key.key`
		compliantPKICRTFilesStats           = `644 0 0 /var/lib/kubelet/pki/crt.crt`
		compliantKubeletServerFilesStats    = `600 0 0 /var/lib/kubelet/pki/kubelet-server-2023.pem`
		nonCompliantCAFileStats             = `664 0 0 /var/lib/kubelet/ca.crt`
		nonCompliantKubeconfigRealFileStats = `644 0 0 /var/lib/kubelet/kubeconfig-real`
		nonCompliantKubeletFileStats        = `644 1000 0 /var/lib/kubelet/config/kubelet`
		nonCompliantKubeletServiceFileStats = `644 0 2000 /etc/systemd/system/kubelet.service`
		nonCompliantPKIAllFilesStats        = `766 0 0 /var/lib/kubelet/pki
644 0 0 /var/lib/kubelet/pki/key.key
664 0 0 /var/lib/kubelet/pki/crt.crt
644 0 0 /var/lib/kubelet/pki/kubelet-server-2023.pem`
		nonCompliantPKIKeyFilesStats        = `644 0 0 /var/lib/kubelet/pki/key.key`
		nonCompliantPKICRTFilesStats        = `664 0 0 /var/lib/kubelet/pki/crt.crt`
		nonCompliantKubeletServerFilesStats = `644 0 0 /var/lib/kubelet/pki/kubelet-server-2023.pem`
		serverTLSBootstrapSetTrue           = `serverTLSBootstrap: true`
		serverTLSBootstrapSetFalse          = `serverTLSBootstrap: false`
	)

	var (
		instanceID             = "1"
		fakeClusterClient      client.Client
		fakeControlPlaneClient client.Client
		controlPlaneNamespace  = "foo"
		dikiPodName            = "diki-node-files-aaaaaaaaaa"
		fakeClusterPodContext  pod.PodContext
		workers                *extensionsv1alpha1.Worker
		ctx                    = context.TODO()
	)

	BeforeEach(func() {
		v1r10.Generator = &FakeRandString{CurrentChar: 'a'}
		fakeClusterClient = fakeclient.NewClientBuilder().Build()
		fakeControlPlaneClient = fakeclient.NewClientBuilder().WithScheme(kubernetesgardener.SeedScheme).Build()

		workers = &extensionsv1alpha1.Worker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "worker1",
				Namespace: controlPlaneNamespace,
			},
			Spec: extensionsv1alpha1.WorkerSpec{
				Pools: []extensionsv1alpha1.WorkerPool{
					{
						Name: "pool1",
					},
					{
						Name: "pool2",
					},
				},
			},
		}
		Expect(fakeControlPlaneClient.Create(ctx, workers)).To(Succeed())

		plainAllocatableNode := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		node1 := plainAllocatableNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		node1.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool1"
		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		node2 := plainAllocatableNode.DeepCopy()
		node2.ObjectMeta.Name = "node2"
		node2.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool2"
		Expect(fakeClusterClient.Create(ctx, node2)).To(Succeed())
	})

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r10.RuleNodeFiles{
				Logger:                testLogger,
				InstanceID:            instanceID,
				ClusterClient:         fakeClusterClient,
				ControlPlaneClient:    fakeControlPlaneClient,
				ControlPlaneNamespace: controlPlaneNamespace,
				ClusterPodContext:     fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return passed checkResults when all files comply",
			[][]string{{rawKubeletCommand, kubeletConfig, kubeletServicePath, compliantCAFileStats, compliantKubeconfigRealFileStats, compliantKubeletFileStats, compliantKubeletServiceFileStats, compliantPKIAllFilesStats},
				{"--config=./config", serverTLSBootstrapSetTrue, compliantKubeletServerFilesStats},
				{"--config=./config", serverTLSBootstrapSetFalse, compliantPKICRTFilesStats, compliantPKIKeyFilesStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil, nil}, {nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/kubeconfig-real, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki, permissions: 755, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/key.key, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/crt.crt, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "pool1", "kind", "workerGroup", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "pool2", "kind", "workerGroup", "details", "fileName: /var/lib/kubelet/pki/crt.crt, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "pool2", "kind", "workerGroup", "details", "fileName: /var/lib/kubelet/pki/key.key, permissions: 600, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when no files comply",
			[][]string{{rawKubeletCommand, kubeletConfig, kubeletServicePath, nonCompliantCAFileStats, nonCompliantKubeconfigRealFileStats, nonCompliantKubeletFileStats, nonCompliantKubeletServiceFileStats, nonCompliantPKIAllFilesStats},
				{"--config=./config", serverTLSBootstrapSetTrue, nonCompliantKubeletServerFilesStats},
				{"--config=./config", serverTLSBootstrapSetTrue, nonCompliantKubeletServerFilesStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil, nil}, {nil, nil, nil}, {nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/kubeconfig-real, permissions: 644, expectedPermissionsMax: 600")),
				rule.FailedCheckResult("File has unexpected owner user", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", gardener.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 2000, expectedOwnerGroups: [0 65534]")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki, permissions: 766, expectedPermissionsMax: 755")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/key.key, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/crt.crt, permissions: 664, expectedPermissionsMax: 755")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "name", "pool1", "kind", "workerGroup", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, permissions: 644, expectedPermissionsMax: 600")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "shoot", "name", "pool2", "kind", "workerGroup", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, permissions: 644, expectedPermissionsMax: 600")),
			}),
		Entry("should return errored checkResults when different function error",
			[][]string{{rawKubeletCommand, kubeletConfig, kubeletServicePath, compliantCAFileStats, emptyFileStats, compliantKubeletFileStats, compliantKubeletServiceFileStats, compliantPKIAllFilesStats},
				{"--feature-gates=some-feature --config=./config"},
				{"--foo=./bar"}},
			[][]error{{nil, nil, nil, errors.New("foo"), nil, nil, nil, errors.New("bar")}, {nil}, {nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", gardener.NewTarget("cluster", "shoot", "name", dikiPodName, "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("Stats not found", gardener.NewTarget("cluster", "shoot", "details", "filePath: /var/lib/kubelet/kubeconfig-real")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, permissions: 644, ownerUser: 0, ownerGroup: 0")),
				rule.ErroredCheckResult("bar", gardener.NewTarget("cluster", "shoot", "name", dikiPodName, "namespace", "kube-system", "kind", "pod")),
				rule.FailedCheckResult("Use of deprecated kubelet config flag feature-gates", gardener.NewTarget("cluster", "shoot", "name", "pool1", "kind", "workerGroup")),
				rule.ErroredCheckResult("kubelet config file has not been set", gardener.NewTarget("cluster", "shoot", "name", "pool2", "kind", "workerGroup")),
			}),
	)
})
