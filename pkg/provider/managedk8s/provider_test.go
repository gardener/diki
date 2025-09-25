// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/managedk8s"
)

// minimal valid kubeconfig for testing
const testKubeconfig = `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: dummytoken
`

var _ = Describe("managedk8s", func() {
	var (
		id, name   string
		kubeconfig *rest.Config
	)

	BeforeEach(func() {
		id = "test_xyz"
		name = "managedk8s_test"
		kubeconfig = &rest.Config{
			Host: "aldebaran",
		}
	})

	Describe("#New", func() {
		It("should return correct provider object when correct values are used", func() {
			provider, err := managedk8s.New(managedk8s.WithID(id), managedk8s.WithName(name), managedk8s.WithConfig(kubeconfig))

			Expect(provider.ID()).To(Equal(id))
			Expect(provider.Name()).To(Equal(name))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("#FromGenericConfig", func() {
		var (
			tmpKubeconfig string
		)

		BeforeEach(func() {
			GinkgoT().Setenv("KUBECONFIG", "")
			tmpKubeconfig = GinkgoT().TempDir() + "/kubeconfig"
			_ = os.WriteFile(tmpKubeconfig, []byte(testKubeconfig), 0600)

			managedk8s.SetInClusterConfigFunc(rest.InClusterConfig)
		})

		It("should create a Provider from valid ProviderConfig with kubeconfigPath", func() {
			args := map[string]interface{}{
				"kubeconfigPath": tmpKubeconfig,
			}
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
				Args: args,
				Metadata: map[string]string{
					"foo": "bar",
				},
			}

			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).NotTo(HaveOccurred())
			Expect(provider.ID()).To(Equal("id"))
			Expect(provider.Name()).To(Equal("name"))
			Expect(provider.Metadata()["foo"]).To(Equal("bar"))
			Expect(provider.Config).NotTo(BeNil())
		})

		It("should create a Provider from valid ProviderConfig with KUBECONFIG env var", func() {
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
				Metadata: map[string]string{
					"foo": "bar",
				},
			}
			GinkgoT().Setenv("KUBECONFIG", tmpKubeconfig)
			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).NotTo(HaveOccurred())
			Expect(provider.ID()).To(Equal("id"))
			Expect(provider.Name()).To(Equal("name"))
			Expect(provider.Metadata()["foo"]).To(Equal("bar"))
			Expect(provider.Config).NotTo(BeNil())
		})

		It("should return error if Args are invalid", func() {
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
				Args: "not-a-map",
			}
			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).To(HaveOccurred())
			Expect(provider).To(BeNil())
		})

		It("should return error if kubeconfig path is invalid", func() {
			args := map[string]interface{}{
				"kubeconfigPath": "/does/not/exist",
			}
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
				Args: args,
			}
			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).To(HaveOccurred())
			Expect(provider).To(BeNil())
		})

		It("should return valid in-cluster config", func() {
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
			}

			managedk8s.SetInClusterConfigFunc(func() (*rest.Config, error) {
				return &rest.Config{
					Host: "in-cluster",
					TLSClientConfig: rest.TLSClientConfig{
						CAData: []byte("foo"),
					},
				}, nil
			})
			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).NotTo(HaveOccurred())
			Expect(provider.ID()).To(Equal("id"))
			Expect(provider.Name()).To(Equal("name"))
			Expect(provider.Config).NotTo(BeNil())
		})

		It("should return error if in-cluster config cannot be loaded", func() {
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
			}
			provider, err := managedk8s.FromGenericConfig(providerConf)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("failed to load in-cluster configuration")))
			Expect(provider).To(BeNil())
		})
	})
})
