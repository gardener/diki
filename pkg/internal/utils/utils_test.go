// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/diki/pkg/internal/utils"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
)

var _ = Describe("utils", func() {
	Describe("#NewFileStats", func() {

		DescribeTable("#MatchCases",
			func(stats, delimiter string, expectedFileStats utils.FileStats, errorMatcher gomegatypes.GomegaMatcher) {
				result, err := utils.NewFileStats(stats, delimiter)

				Expect(err).To(errorMatcher)
				Expect(result).To(Equal(expectedFileStats))
			},
			Entry("Should return correct FileStats object",
				"600\t0\t1000\tregular file\t/destination/file 1.txt", "\t",
				utils.FileStats{Path: "/destination/file 1.txt", Permissions: "600", UserOwner: "0", GroupOwner: "1000", FileType: "regular file"}, BeNil()),
			Entry("Should return error when stats are not full",
				"600\t0\t1000\t/destination/file1.txt", "\t",
				utils.FileStats{}, MatchError("stats: 600\t0\t1000\t/destination/file1.txt, not in correct format: '${permissions}\t${userOwner}\t${groupOwner}\t${fileType}\t${filePath}'")),
		)
	})
	Describe("#GetPodMountedFileStatResults", func() {
		const (
			mounts = `[
  {
    "destination": "/destination",
    "source": "/destination"
  }, 
  {
    "destination": "/foo",
    "source": "/foo"
  },
  {
    "destination": "/bar",
    "source": "/source"
  }
]`
			destinationStats = "600\t0\t0\tregular file\t/destination/file1.txt\n"
			fooStats         = "644\t0\t65532\tregular file\t/foo/file2.txt\n"
		)
		var (
			fakePodExecutor      *fakepod.FakePodExecutor
			destinationFileStats utils.FileStats
			fooFileStats         utils.FileStats
			ctx                  context.Context
			pod                  corev1.Pod
		)
		BeforeEach(func() {
			destinationFileStats = utils.FileStats{
				Path:        "/destination/file1.txt",
				Permissions: "600",
				UserOwner:   "0",
				GroupOwner:  "0",
				FileType:    "regular file",
			}
			fooFileStats = utils.FileStats{
				Path:        "/foo/file2.txt",
				Permissions: "644",
				UserOwner:   "0",
				GroupOwner:  "65532",
				FileType:    "regular file",
			}
			pod = corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "test",
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/destination",
								},
								{
									Name:      "bar",
									MountPath: "/bar",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "bar",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:        "test",
							ContainerID: "containerd://bar",
						},
					},
				},
			}

			ctx = context.TODO()
		})

		It("Should return correct single stats", func() {
			executeReturnString := []string{mounts, destinationStats}
			executeReturnError := []error{nil, nil}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(BeNil())
			Expect(result).To(Equal(map[string][]utils.FileStats{"test": {destinationFileStats}}))
		})

		It("Should return correct multiple stats", func() {
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				MountPath: "/foo",
			})
			executeReturnString := []string{mounts, destinationStats, fooStats}
			executeReturnError := []error{nil, nil, nil}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(BeNil())
			Expect(result).To(Equal(map[string][]utils.FileStats{"test": {destinationFileStats, fooFileStats}}))
		})

		It("Should return error when file could not be found", func() {
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				MountPath: "/foo",
			})
			executeReturnString := []string{mounts, destinationStats, ""}
			executeReturnError := []error{nil, nil, nil}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(MatchError("could not find file /foo"))
			Expect(result).To(Equal(map[string][]utils.FileStats{"test": {destinationFileStats}}))
		})

		It("Should error when there are problems with container", func() {
			pod.Spec.Containers = []corev1.Container{
				{
					Name: "foo",
				},
				{
					Name: "bar",
				},
				{
					Name: "baz",
				},
			}
			pod.Status = corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:        "bar",
						ContainerID: "",
					},
					{
						Name:        "baz",
						ContainerID: "fake",
					},
				},
			}
			executeReturnString := []string{}
			executeReturnError := []error{}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(MatchError("container with Name foo not (yet) in status\ncontainer with Name bar not (yet) running\ncannot handle container with Name baz"))
			Expect(result).To(Equal(map[string][]utils.FileStats{}))
		})

		It("Should error when first command errors", func() {
			executeReturnString := []string{mounts}
			executeReturnError := []error{errors.New("command error")}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(MatchError("command error"))
			Expect(result).To(Equal(map[string][]utils.FileStats{}))
		})

		It("Should return stats when a command errors", func() {
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				MountPath: "/foo",
			})
			executeReturnString := []string{mounts, destinationStats, fooStats}
			executeReturnError := []error{nil, errors.New("command error"), nil}
			fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
			result, err := utils.GetMountedFilesStats(ctx, "", fakePodExecutor, pod, []string{"/lib/modules"})

			Expect(err).To(MatchError("command error"))
			Expect(result).To(Equal(map[string][]utils.FileStats{"test": {fooFileStats}}))
		})
	})

	DescribeTable("#ExceedFilePermissions",
		func(filePermissions, filePermissionsMax string, expectedResult bool, errorMatcher gomegatypes.GomegaMatcher) {
			result, err := utils.ExceedFilePermissions(filePermissions, filePermissionsMax)

			Expect(result).To(Equal(expectedResult))
			Expect(err).To(errorMatcher)
		},
		Entry("should return false when filePermissions do not exceed filePermissionsMax",
			"0600", "0644", false, BeNil()),
		Entry("should return false when filePermissions equal filePermissionsMax",
			"0644", "0644", false, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by user permissions",
			"0700", "0644", true, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by group permissions",
			"0460", "0644", true, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by other permissions",
			"0406", "0644", true, BeNil()),
	)
})
