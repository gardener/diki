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
	const (
		enabledAnonymousAuthServer  = "https://enabled-anonymous-auth-example.com"
		disabledAnonymousAuthServer = "https://disabled-anonymous-auth-example.com"
		unreachableServer           = "https://unreachable-server-example.com"
	)

	var (
		mockClient *http.Client
		ctx        = context.TODO()
	)

	BeforeEach(func() {
		mockClient = manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case enabledAnonymousAuthServer:
				return &http.Response{StatusCode: http.StatusForbidden}, nil
			case disabledAnonymousAuthServer:
				return &http.Response{StatusCode: http.StatusUnauthorized}, nil
			default:
				return &http.Response{StatusCode: http.StatusNotFound}, http.ErrHandlerTimeout
			}
		})
	})

	DescribeTable("Run cases",
		func(hostURL string, expectedResult []rule.CheckResult) {
			r := rules.Rule242390{
				KAPIExternalURL: hostURL,
				Client:          mockClient,
			}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedResult))
		},
		Entry("should fail when the kube-apiserver anonymous authentication is enabled", enabledAnonymousAuthServer, []rule.CheckResult{
			rule.FailedCheckResult("kube-apiserver has anonymous authentication enabled", rule.NewTarget()),
		}),
		Entry("should pass when the kube-apiserver anonymous authentication is disabled", disabledAnonymousAuthServer, []rule.CheckResult{
			rule.PassedCheckResult("kube-apiserver has anonymous authentication disabled", rule.NewTarget()),
		}),
		Entry("should error when the kube-apiserver URL can not be resolved", unreachableServer, []rule.CheckResult{
			rule.ErroredCheckResult("could not access kube-apiserver: Get \"https://unreachable-server-example.com\": http: Handler timeout", rule.NewTarget()),
		}),
	)
})
