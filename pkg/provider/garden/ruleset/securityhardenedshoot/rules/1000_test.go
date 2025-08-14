// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#1000", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()

		shoot *gardencorev1beta1.Shoot

		shootName      = "foo"
		shootNamespace = "bar"

		r        rule.Rule
		ruleID   = "1000"
		ruleName = "Shoot clusters should enable required extensions."
		severity = rule.SeverityMedium
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: shootName, Namespace: shootNamespace}}
	})

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options1000, expectedCheckResults []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1000{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Options:        options,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")},
			},
		),
		Entry("should return a passed check result if a provided option configuration is not present",
			func() {},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "There are no required extensions.", Target: rule.NewTarget()},
			},
		),
		Entry("should return a passed check result if there are no expected extensions to check",
			func() {},
			&rules.Options1000{
				[]rules.Extension{},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "There are no required extensions.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when a listed extension cannot be found",
			func() {
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "foo",
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension foo is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when a listed extension is enabled by default",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/foo": "true",
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension foo is enabled for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when a listed extension is added to the extension list in the shoot spec",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/foo": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "foo",
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension foo is enabled for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when a listed extension is added to the extension list in the shoot spec and explicitly enabled",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/foo": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type:     "foo",
						Disabled: ptr.To(false),
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension foo is enabled for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should warn when a listed extension is enabled in the shoot labels and disabled in the shoot spec",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/foo": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type:     "foo",
						Disabled: ptr.To(true),
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Warning, Message: "Extension foo is disabled in the shoot spec and enabled in labels.", Target: rule.NewTarget()},
			},
		),
		Entry("should warn when a listed extension has unecpected value in the shoot labels",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/foo": "false",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "foo",
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "foo",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Warning, Message: "Extension foo has unexpected label value: false.", Target: rule.NewTarget()},
			},
		),
		Entry("should create a check result for each provided extension in the configuration",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/one": "true",
					"extensions.extensions.gardener.cloud/two": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "one",
					},
					{
						Type:     "two",
						Disabled: ptr.To(false),
					},
					{
						Type:     "three",
						Disabled: ptr.To(true),
					},
				}
			},
			&rules.Options1000{Extensions: []rules.Extension{
				{
					Type: "one",
				},
				{
					Type: "two",
				},
				{
					Type: "three",
				},
				{
					Type: "four",
				},
			},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension one is enabled for the shoot cluster.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Extension two is enabled for the shoot cluster.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "Extension three is not configured for the shoot cluster.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "Extension four is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
	)

	Describe("#ValidateOptions", func() {
		It("should not error when options are correct", func() {
			options := rules.Options1000{
				Extensions: []rules.Extension{
					{
						Type: "foo",
					},
					{
						Type: "bar",
					},
				},
			}

			result := options.Validate(nil)
			Expect(result).To(BeEmpty())
		})
		It("should error when options are incorrect", func() {
			options := rules.Options1000{
				Extensions: []rules.Extension{
					{
						Type: "foo",
					},
					{
						Type: "",
					},
				},
			}
			result := options.Validate(nil)
			Expect(result).To(Equal(field.ErrorList{
				{
					Type:     field.ErrorTypeRequired,
					Field:    "extensions[1].type",
					BadValue: "",
					Detail:   "must not be empty",
				},
			}))
		})
	})
})
