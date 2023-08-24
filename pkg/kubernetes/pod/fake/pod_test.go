// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
)

var _ = Describe("pod", func() {
	Describe("#FakeSimplePodContext", func() {
		var (
			ctx = context.TODO()
		)

		It("should create correct PodExecutor", func() {
			executeReturnString := [][]string{{"foo"}, {"bar"}}
			executeReturnError := [][]error{{nil}, {errors.New("error")}}
			mspc := fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)

			mpe1, err := mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(BeNil())

			returnString, returnError := mpe1.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			mpe2, err := mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(BeNil())

			returnString, returnError = mpe2.Execute(ctx, "", "")

			Expect(returnString).To(Equal("bar"))
			Expect(returnError).To(MatchError("error"))
		})

		It("should return correct error when not enough not enough return strings have been faked", func() {
			executeReturnString := [][]string{{"foo"}}
			executeReturnError := [][]error{{nil}, {errors.New("error")}}
			mspc := fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)

			mpe1, err := mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(BeNil())

			returnString, returnError := mpe1.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			_, err = mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(MatchError("not enough return strings have been faked"))
		})

		It("should return correct error when not enough not enough return errors have been faked", func() {
			executeReturnString := [][]string{{"foo"}, {"bar"}}
			executeReturnError := [][]error{{nil}}
			mspc := fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)

			mpe1, err := mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(BeNil())

			returnString, returnError := mpe1.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			_, err = mspc.Create(ctx, func() *corev1.Pod { return &corev1.Pod{} })
			Expect(err).To(MatchError("not enough return errors have been faked"))
		})

		It("should return nil when delete method is called", func() {
			executeReturnString := [][]string{{"foo"}}
			executeReturnError := [][]error{{nil}}
			mspc := fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)

			err := mspc.Delete(ctx, "", "")

			Expect(err).To(BeNil())
		})
	})

	Describe("#FakePodExecutor", func() {
		var (
			ctx = context.TODO()
		)

		It("should fake execute returns correctly", func() {
			executeReturnString := []string{"foo", "bar"}
			executeReturnError := []error{nil, errors.New("error")}

			mpe := fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)

			returnString, returnError := mpe.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			returnString, returnError = mpe.Execute(ctx, "", "")

			Expect(returnString).To(Equal("bar"))
			Expect(returnError).To(MatchError("error"))
		})

		It("should return correct error when not enough not enough return strings have been faked", func() {
			executeReturnString := []string{"foo"}
			executeReturnError := []error{nil, errors.New("error")}

			mpe := fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)

			returnString, returnError := mpe.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			returnString, returnError = mpe.Execute(ctx, "", "")
			Expect(returnString).To(Equal(""))
			Expect(returnError).To(MatchError("not enough return strings have been faked"))
		})

		It("should return correct error when not enough not enough return errors have been faked", func() {
			executeReturnString := []string{"foo", "bar"}
			executeReturnError := []error{nil}

			mpe := fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)

			returnString, returnError := mpe.Execute(ctx, "", "")

			Expect(returnString).To(Equal("foo"))
			Expect(returnError).To(BeNil())

			returnString, returnError = mpe.Execute(ctx, "", "")
			Expect(returnString).To(Equal(""))
			Expect(returnError).To(MatchError("not enough return errors have been faked"))
		})
	})
})
