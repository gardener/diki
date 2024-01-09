// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/gardener/diki/pkg/kubernetes/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
)

// FileStats contains single file stats
type FileStats struct {
	Path                  string
	Permissions           string
	UserOwner, GroupOwner string
	FileType              string
	ContainerName         string
}

// NewFileStats creates a new FileStats object from the result of
// stat command called with `-c "%a %u %g %F %n"` flag and value
func NewFileStats(stats, pathUsedToFindFile, containerName string) (*FileStats, error) {
	statsSlice := strings.Split(stats, " ")

	if len(statsSlice) < 5 {
		return &FileStats{}, fmt.Errorf("stats: %s, not in correct format: '${permissions} ${userOwner} ${groupOwner} ${fileType} ${filePath}'", stats)
	}

	fileType := statsSlice[3]
	var filePath string

	// the file type %F can have " " characters. Ex: "regular file"
	for i := 4; i < len(statsSlice); i++ {
		if strings.HasPrefix(statsSlice[i], pathUsedToFindFile) {
			filePath = strings.Join(statsSlice[i:], " ")
			break
		}
		fileType = fmt.Sprintf("%s %s", fileType, statsSlice[i])
	}

	if len(filePath) == 0 {
		return &FileStats{}, fmt.Errorf("stats: %s, not in correct format: '${permissions} ${userOwner} ${groupOwner} ${fileType} ${filePath}'", stats)
	}

	fileStats := &FileStats{
		Path:          filePath,
		Permissions:   statsSlice[0],
		UserOwner:     statsSlice[1],
		GroupOwner:    statsSlice[2],
		FileType:      fileType,
		ContainerName: containerName,
	}

	return fileStats, nil
}

// Name returns the base name of the file
func (fs *FileStats) Name() string {
	return filepath.Base(fs.Path)
}

// Dir returns the dir of the file
func (fs *FileStats) Dir() string {
	return filepath.Dir(fs.Path)
}

// GetPodMountedFileStatResults returns a string containing the stat results of all
// mounted files of a podwith the exception of file mounted at `/dev/termination-log`
func GetPodMountedFileStatResults(
	ctx context.Context,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	execContainerPath string,
	excludedSources []string,
) ([]FileStats, error) {
	stats := []FileStats{}
	var err error

	for _, container := range pod.Spec.Containers {
		containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
			return containerStatus.Name == container.Name
		})

		if containerStatusIdx < 0 {
			err = errors.Join(err, fmt.Errorf("container with Name %s not (yet) in status", container.Name))
			continue
		}

		containerID := pod.Status.ContainerStatuses[containerStatusIdx].ContainerID
		switch {
		case len(containerID) == 0:
			err = errors.Join(err, fmt.Errorf("container with Name %s not (yet) running", container.Name))
		case strings.HasPrefix(containerID, "containerd://"):
			baseContainerID := strings.Split(containerID, "//")[1]
			containerStats, err2 := getContainerMountedFileStatResults(ctx,
				podExecutor,
				pod,
				container.Name,
				baseContainerID,
				execContainerPath,
				excludedSources,
			)
			if err2 != nil {
				err = errors.Join(err, err2)
			}

			stats = append(stats, containerStats...)
		default:
			err = errors.Join(err, fmt.Errorf("cannot handle container with Name %s", container.Name))
		}
	}
	return stats, err
}

func getContainerMountedFileStatResults(
	ctx context.Context,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	containerName, containerID, execContainerPath string,
	excludedSources []string,
) ([]FileStats, error) {
	stats := []FileStats{}
	var err error

	commandResult, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`%s/usr/local/bin/nerdctl --namespace k8s.io inspect --mode=native %s | jq -r .[0].Spec.mounts`, execContainerPath, containerID))
	if err != nil {
		return stats, err
	}

	mounts := []config.Mount{}
	err = json.Unmarshal([]byte(commandResult), &mounts)
	if err != nil {
		return stats, err
	}
	excludedSourcesSet := sets.New(excludedSources...)

	for _, mount := range mounts {
		if strings.HasPrefix(mount.Source, "/") &&
			!matchHostPathSources(excludedSourcesSet, mount.Destination, containerName, &pod) &&
			isMountRequiredByContainer(mount.Destination, containerName, &pod) &&
			mount.Destination != "/dev/termination-log" {
			mountStats, err2 := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -type f -exec stat -Lc "%%a %%u %%g %%F %%n" {} \;`, mount.Source))

			if err2 != nil {
				err = errors.Join(err, err2)
				continue
			}

			mountStatsSlice := strings.Split(strings.TrimSpace(mountStats), "\n")
			for _, mountStats := range mountStatsSlice {
				mountStatsFile, err2 := NewFileStats(mountStats, mount.Source, containerName)
				if err2 != nil {
					err = errors.Join(err, err2)
					continue
				}

				stats = append(stats, *mountStatsFile)
			}

		}
	}
	return stats, err
}

func isMountRequiredByContainer(destination, containerName string, pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != containerName {
			continue
		}
		if containsDestination := slices.ContainsFunc(container.VolumeMounts, func(volumeMount corev1.VolumeMount) bool {
			return volumeMount.MountPath == destination
		}); containsDestination {
			return true
		}
	}
	return false
}

func matchHostPathSources(sources sets.Set[string], destination, containerName string, pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != containerName {
			continue
		}
		volumeMountIdx := slices.IndexFunc(container.VolumeMounts, func(volumeMount corev1.VolumeMount) bool {
			return volumeMount.MountPath == destination
		})

		if volumeMountIdx < 0 {
			return false
		}

		volumeIdx := slices.IndexFunc(pod.Spec.Volumes, func(volume corev1.Volume) bool {
			return volume.Name == container.VolumeMounts[volumeMountIdx].Name
		})

		if volumeIdx < 0 {
			return false
		}

		volume := pod.Spec.Volumes[volumeIdx]

		return volume.HostPath != nil && sources.Has(volume.HostPath.Path)
	}
	return false
}
