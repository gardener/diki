// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	manualfake "k8s.io/client-go/rest/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242390", func() {

	var (
		mockClient                  *http.Client
		enabledAnonymousAuthServer  = "https://enabled-anonymous-auth-example.com"
		disabledAnonymousAuthServer = "https://disabled-anonymous-auth-example.com"
		unreachableServer           = "https://unreachable-server-example.com"
	)

	BeforeEach(func() {
		mockClient = manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case enabledAnonymousAuthServer:
				return &http.Response{StatusCode: http.StatusUnauthorized}, nil
			case disabledAnonymousAuthServer:
				return &http.Response{StatusCode: http.StatusForbidden}, nil
			default:
				return &http.Response{StatusCode: http.StatusNotFound}, http.ErrHandlerTimeout
			}
		})
	})

	It("should fail when the kube-apiserver anonymous authentication is enabled", func() {
		r := rules.Rule242390{
			KAPIExternalURL: enabledAnonymousAuthServer,
			Client:          mockClient,
		}
		ruleResult, err := r.Run(context.TODO())
		Expect(err).To(BeNil())

		expectedResult := []rule.CheckResult{
			rule.FailedCheckResult("kube-apiserver has anonymous authentication enabled", rule.NewTarget()),
		}
		Expect(ruleResult.CheckResults).To(Equal(expectedResult))
	})

	It("should pass when the kube-apiserver anonymous authentication is disabled", func() {
		r := rules.Rule242390{
			KAPIExternalURL: disabledAnonymousAuthServer,
			Client:          mockClient,
		}
		ruleResult, err := r.Run(context.TODO())
		Expect(err).To(BeNil())

		expectedResult := []rule.CheckResult{
			rule.PassedCheckResult("kube-apiserver has anonymous authentication disabled", rule.NewTarget()),
		}
		Expect(ruleResult.CheckResults).To(Equal(expectedResult))
	})

	It("should error when the kube-apiserver URL can not be resolved", func() {
		r := rules.Rule242390{
			KAPIExternalURL: unreachableServer,
			Client:          mockClient,
		}
		ruleResult, err := r.Run(context.TODO())
		Expect(err).To(BeNil())

		expectedResult := []rule.CheckResult{
			rule.ErroredCheckResult("failed to access the kube-apiserver", rule.NewTarget()),
		}
		Expect(ruleResult.CheckResults).To(Equal(expectedResult))
	})

})
