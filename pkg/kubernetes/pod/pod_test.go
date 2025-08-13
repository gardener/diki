// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/pod"
)

var _ = Describe("pod", func() {
	Describe("#NewSimplePodContext", func() {
		var (
			fakeClient client.Client
			fakeConfig *rest.Config
			ctx        = context.TODO()
			name       = "foo"
			namespace  = "foo"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			fakeConfig = &rest.Config{
				Host: "foo",
			}
		})

		It("should create diki pod", func() {
			spc, err := pod.NewSimplePodContext(fakeClient, fakeConfig, map[string]string{})
			Expect(err).To(BeNil())

			_, err = spc.Create(ctx, fakePodConstructor(name, namespace, ""))
			Expect(err).To(BeNil())

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}

			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)
			Expect(err).To(BeNil())
		})

		It("should create diki pod with correct labels", func() {
			spc, err := pod.NewSimplePodContext(fakeClient, fakeConfig, map[string]string{
				"foo":     "not-bar",
				"bar":     "foo",
				"foo-bar": "bar",
			})
			Expect(err).To(BeNil())

			_, err = spc.Create(ctx, fakePodConstructor(name, namespace, ""))
			Expect(err).To(BeNil())

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}
			expectedLabels := map[string]string{
				"foo":     "bar",
				"bar":     "foo",
				"foo-bar": "bar",
			}

			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)
			Expect(err).To(BeNil())
			Expect(pod.Labels).To(Equal(expectedLabels))
		})

		It("should delete diki pod", func() {
			spc, err := pod.NewSimplePodContext(fakeClient, fakeConfig, map[string]string{})
			Expect(err).To(BeNil())

			_, err = spc.Create(ctx, fakePodConstructor(name, namespace, ""))
			Expect(err).To(BeNil())

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}

			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)
			Expect(err).To(BeNil())

			err = spc.Delete(ctx, name, namespace)
			Expect(err).To(BeNil())

			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			}

			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)
			Expect(err).To(MatchError("pods \"foo\" not found"))
		})
	})
})

func fakePodConstructor(name, namespace, nodeName string) func() *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	if nodeName != "" {
		pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": nodeName}
	}

	return func() *corev1.Pod {
		return pod
	}
}
