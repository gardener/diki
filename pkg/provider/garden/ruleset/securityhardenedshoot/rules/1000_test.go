// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("#1000", func() {
	var (
		fakeClient = client.Client
		ctx        = context.TODO()

		shoot *gardencorev1beta.Shoot

		shootName      = "foo"
		shootNamespace = "bar"

		ruleID   = "1000"
		ruleName = "Shoot clusters should enable required extensions. This rule can be configured as per organisation's requirements in order to check if required extensions are enabled for the shoot cluster."
		severity = rule.SeverityHigh
	)

	BeforeEach(func() {

	})
})
