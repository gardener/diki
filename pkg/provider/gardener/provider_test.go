// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/provider/gardener"
)

var _ = Describe("gardener", func() {
	var (
		id, name                string
		shootConfig, seedConfig *rest.Config
		args                    gardener.Args
	)

	BeforeEach(func() {
		id = "test"
		name = "test"
		shootConfig = &rest.Config{
			Host: "foo",
		}
		seedConfig = &rest.Config{
			Host: "bar",
		}
	})

	Describe("#New", func() {
		It("should return correct provider object when correct values are used.", func() {
			provider, err := gardener.New(
				gardener.WithID(id),
				gardener.WithName(name),
				gardener.WithShootConfig(shootConfig),
				gardener.WithSeedConfig(seedConfig),
				gardener.WithArgs(args),
			)

			Expect(provider.ID()).To(Equal(id))
			Expect(provider.Name()).To(Equal(name))
			Expect(provider.Args.ShootName).To(Equal(args.ShootName))
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
