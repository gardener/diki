// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s_test

import (
	"os"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/managedk8s"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
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

const cert = `
-----BEGIN CERTIFICATE-----
MIID5jCCAk6gAwIBAgIQC8l0jvV8MEIgws6kbTeDljANBgkqhkiG9w0BAQsFADAN
MQswCQYDVQQDEwJjYTAeFw0yNTA4MTUxMTI1NTlaFw0zNTA4MTUxMTI2NTlaMA0x
CzAJBgNVBAMTAmNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArfPm
yq9EgKpFWjHpGNQyWqX3yE/AA5lhcDuisB626jKecqC9T0jzdNY4CzUCcHI91Db8
dhAn1JhJLZFZK4Bmfdc8T+80ppcBQEwNlWagAiiM1hLyO8RiIrf5H+5mPtZQAkHX
XO1IQDPBgflq4xG35BKazJNGbV9tnw92b7PPf+xTIdrutNdH/iZ/mZ219f4rwiTm
Vq/J9fU/eAKypF5xkUVMG2LIjt0YwZajWFb9ZAjxsHZLHGYSwPMwGBTG1j2DlEl2
ETlNL+HgdcovKoT/Aq7JkewqVcFzfWr2SFQYGcWk0m8XyBDtCHyW1COiqpVytj7i
jEPRP/kMZc54gZdfaN6sGRtqqSvss63zgrFfl0R+coy/9zDR8HGomB9Oxmx010Qn
gy+cKzYQ+T9tvFFfJRhpB5t6oefxpw1Aitlt2HIY3V8969AXePFptJJ5hy4/mY56
e9wzdy/aWV//uJiK7rRDX7uFzpMM/JMaRjtbANtuBBFjJ9hyluS1p201YRTTAgMB
AAGjQjBAMA4GA1UdDwEB/wQEAwIBpjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBThpDavXDiBnosV/XpLTD/BkHeGXDANBgkqhkiG9w0BAQsFAAOCAYEAogsGWHVX
2lziUENFyVXMAryw0dIFmIoAGelr3gOTKnNUlsvQvLm3BmOaEnVEbD0Du2tinW++
YviEP23GR5UOTcy7jsTdSug2o3WCnG8a9It5LpCCWocH4KwA2vMDb+0bXMEdNKV9
AvTnQj1gNyUG+zmWzF7h3AIMi3vVgHwcZjIbENh565VVQ+PhI9IodlKOuaRUD/je
7uXJUQf9PusJ1AVgjnENnFW68cLD+7rfCCqkuMLoKW8zVCv8xEFAiEXCBVYxVTPo
kbLv/IM6BgvExBrqpycSncturauXavzB23jpKrVnD758esTna/FYlVgAiXR7nSxi
hyiC4xNxo3cAeeoE4Cx8tpJgzaSGPyua2t8jrjF/0JzoJU3Gg7BmUKo+4WXtUysR
oAAohsGDJiuRLls58aitRZWBfDNSUI0I06G5oiM4AU+6CUe3i68ckAaekAfzr3JH
LrtUc5/X9UqSg9YPiQ2qj55Ge5TKMC3FPQnmQpxK6gCMezmBgagcf7tn
-----END CERTIFICATE-----
`

var _ = Describe("managedk8s.provider", func() {
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
		It("should return correct provider object when correct values are used.", func() {
			provider, err := managedk8s.New(managedk8s.WithID(id), managedk8s.WithName(name), managedk8s.WithConfig(kubeconfig))

			Expect(provider.ID()).To(Equal(id))
			Expect(provider.Name()).To(Equal(name))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("#FromGenericConfig", func() {
		var (
			tmpKubeconfig string
			origEnv       string
			restoreEnv    func()
			options       managedk8s.ConfigOptions
		)

		BeforeEach(func() {
			// Backup and restore KUBECONFIG env var
			origEnv = os.Getenv("KUBECONFIG")
			restoreEnv = func() {
				os.Setenv("KUBECONFIG", origEnv)
			}
			// Create a temp kubeconfig file
			tmpKubeconfig = GinkgoT().TempDir() + "/kubeconfig"
			os.WriteFile(tmpKubeconfig, []byte(testKubeconfig), 0644)

			// Set empty config options
			options = managedk8s.ConfigOptions{
				ConfigGetter: nil,
			}
		})

		AfterEach(func() {
			if restoreEnv != nil {
				restoreEnv()
			}
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

			provider, err := managedk8s.FromGenericConfig(providerConf, options)
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
			os.Setenv("KUBECONFIG", tmpKubeconfig)
			provider, err := managedk8s.FromGenericConfig(providerConf, options)
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
			_, err := managedk8s.FromGenericConfig(providerConf, options)
			Expect(err).To(HaveOccurred())
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
			_, err := managedk8s.FromGenericConfig(providerConf, options)
			Expect(err).To(HaveOccurred())
		})

		It("should return valid in-cluster config", func() {
			providerConf := config.ProviderConfig{
				ID:   "id",
				Name: "name",
			}

			// Create a temp cert file
			tmpCertFile := GinkgoT().TempDir() + "/ca.crt"
			os.WriteFile(tmpCertFile, []byte(cert), 0644)

			options.ConfigGetter = func() (*rest.Config, error) {
				return &rest.Config{
					Host: "in-cluster",
					TLSClientConfig: rest.TLSClientConfig{
						CAFile: tmpCertFile,
					},
				}, nil
			}
			provider, err := managedk8s.FromGenericConfig(providerConf, options)
			Expect(err).NotTo(HaveOccurred())
			Expect(provider.ID()).To(Equal("id"))
			Expect(provider.Name()).To(Equal("name"))
			Expect(provider.Config).NotTo(BeNil())

		})

	})

})
