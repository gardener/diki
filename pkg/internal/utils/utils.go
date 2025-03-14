// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/gardener/diki/pkg/kubernetes/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/rule"
)

// FileStats contains single file stats
type FileStats struct {
	Path                  string
	Permissions           string
	UserOwner, GroupOwner string
	FileType              string
}

// NewFileStats creates a new FileStats object from the result of
// stat command called with `-c "%a %u %g %F %n"` flag and value
func NewFileStats(stats, delimiter string) (FileStats, error) {
	statsSlice := strings.Split(stats, delimiter)

	if len(statsSlice) != 5 {
		return FileStats{}, fmt.Errorf("stats: %s, not in correct format: '${permissions}%[2]s${userOwner}%[2]s${groupOwner}%[2]s${fileType}%[2]s${filePath}'", stats, delimiter)
	}

	return FileStats{
		Path:        statsSlice[4],
		Permissions: statsSlice[0],
		UserOwner:   statsSlice[1],
		GroupOwner:  statsSlice[2],
		FileType:    statsSlice[3],
	}, nil
}

// Base calls [filepath.Base] on [Path]
func (fs FileStats) Base() string {
	return filepath.Base(fs.Path)
}

// Dir calls [filepath.Dir] on [Path]
func (fs FileStats) Dir() string {
	return filepath.Dir(fs.Path)
}

// GetSingleFileStats returns file stats for a specified file
func GetSingleFileStats(
	ctx context.Context,
	podExecutor pod.PodExecutor,
	filePath string,
) (FileStats, error) {
	stats := FileStats{}
	delimiter := "\t"
	statsRaw, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a%[1]s%%u%[1]s%%g%[1]s%%F%[1]s%%n" %s`, delimiter, filePath))
	if err != nil {
		return stats, err
	}
	if len(statsRaw) == 0 {
		return stats, fmt.Errorf("could not find file %s", filePath)
	}

	stat := strings.Split(strings.TrimSpace(statsRaw), "\n")[0]

	stats, err = NewFileStats(stat, delimiter)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// GetFileStatsByDir returns file stats for files in a specific directory
func GetFileStatsByDir(
	ctx context.Context,
	podExecutor pod.PodExecutor,
	dirPath string,
) ([]FileStats, error) {
	var fileStats []FileStats
	delimiter := "\t"
	statsRaw, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -type f -exec stat -Lc "%%a%[2]s%%u%[2]s%%g%[2]s%%F%[2]s%%n" {} \;`, dirPath, delimiter))
	if err != nil {
		return fileStats, err
	}
	if len(statsRaw) == 0 {
		fileNum, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -type f | wc -l`, dirPath))
		if err != nil {
			return fileStats, err
		}

		if fileNum != "0\n" {
			return fileStats, fmt.Errorf("could not find files in %s", dirPath)
		}
		return fileStats, nil
	}

	statsRawSlice := strings.Split(strings.TrimSpace(statsRaw), "\n")
	for _, fileStatString := range statsRawSlice {
		fileStat, err2 := NewFileStats(fileStatString, delimiter)
		if err2 != nil {
			err = errors.Join(err, err2)
			continue
		}

		fileStats = append(fileStats, fileStat)
	}

	return fileStats, nil
}

// GetMountedFilesStats returns file stats grouped by container name for all
// mounted files in a pod with the exception of files mounted at `/dev/termination-log` destination.
// Host sources can be exluded by setting excludeSources.
func GetMountedFilesStats(
	ctx context.Context,
	podExecutorRootPath string,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	excludeSources []string,
) (map[string][]FileStats, error) {
	stats := map[string][]FileStats{}
	var err error

	for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
		containerStats, err2 := getContainerMountedFileStatResults(ctx,
			podExecutorRootPath,
			podExecutor,
			pod,
			container,
			excludeSources,
		)
		if err2 != nil {
			err = errors.Join(err, err2)
		}

		if len(containerStats) > 0 {
			stats[container.Name] = containerStats
		}
	}

	return stats, err
}

// GetContainerID iterates over the passed container names and tries to find a match in the pod container status.
// It returns the container ID of the first match.
func GetContainerID(pod corev1.Pod, containerNames ...string) (string, error) {
	for _, containerName := range containerNames {
		containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
			return containerStatus.Name == containerName
		})

		var containerID string
		if containerStatusIdx < 0 {
			initContainerStatusIdx := slices.IndexFunc(pod.Status.InitContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
				return containerStatus.Name == containerName
			})
			if initContainerStatusIdx < 0 {
				continue
			}
			containerID = pod.Status.InitContainerStatuses[initContainerStatusIdx].ContainerID
		} else {
			containerID = pod.Status.ContainerStatuses[containerStatusIdx].ContainerID
		}

		switch {
		case len(containerID) == 0:
			return "", fmt.Errorf("container with name %s not (yet) running", containerName)
		case strings.HasPrefix(containerID, "containerd://"):
			return strings.Split(containerID, "//")[1], nil
		default:
			return "", fmt.Errorf("cannot handle container with name %s", containerName)
		}
	}
	return "", fmt.Errorf("container with name in %v not (yet) in status", containerNames)
}

// GetContainerMounts returns the container mounts of a container
func GetContainerMounts(
	ctx context.Context,
	podExecutorRootPath string,
	podExecutor pod.PodExecutor,
	containerID string,
) ([]config.Mount, error) {
	commandResult, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`%s/usr/local/bin/nerdctl --namespace k8s.io inspect --mode=native %s | jq -r .[0].Spec.mounts`, podExecutorRootPath, containerID))
	if err != nil {
		return nil, err
	}

	var mounts []config.Mount
	err = json.Unmarshal([]byte(commandResult), &mounts)
	if err != nil {
		return nil, err
	}

	return mounts, nil
}

func getContainerMountedFileStatResults(
	ctx context.Context,
	podExecutorRootPath string,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	container corev1.Container,
	excludedSources []string,
) ([]FileStats, error) {
	var (
		stats []FileStats
		err   error
	)

	containerID, err := GetContainerID(pod, container.Name)
	if err != nil {
		return stats, err
	}

	mounts, err := GetContainerMounts(ctx, podExecutorRootPath, podExecutor, containerID)
	if err != nil {
		return stats, err
	}
	excludedSourcesSet := sets.New(excludedSources...)

	for _, mount := range mounts {
		if strings.HasPrefix(mount.Source, "/") &&
			!matchHostPathSources(excludedSourcesSet, mount.Destination, container, pod) &&
			isMountRequiredByContainer(mount.Destination, container) &&
			mount.Destination != "/dev/termination-log" {
			mountFileStats, err2 := GetFileStatsByDir(ctx, podExecutor, mount.Source)
			if err2 != nil {
				err = errors.Join(err, err2)
				continue
			}
			stats = append(stats, mountFileStats...)
		}
	}
	return stats, err
}

func isMountRequiredByContainer(destination string, container corev1.Container) bool {
	return slices.ContainsFunc(container.VolumeMounts, func(volumeMount corev1.VolumeMount) bool {
		return volumeMount.MountPath == destination
	})
}

func matchHostPathSources(sources sets.Set[string], destination string, container corev1.Container, pod corev1.Pod) bool {
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

// ExceedFilePermissions returns true if any of the user, group or other permissions
// exceed their counterparts in what is passed as max permissions.
//
// Examples where filePermissions do not exceed filePermissionsMax:
//
//	filePermissions = "0004" filePermissionsMax = "0644"
//	filePermissions = "0444" filePermissionsMax = "0644"
//	filePermissions = "0600" filePermissionsMax = "0644"
//	filePermissions = "0644" filePermissionsMax = "0644"
//
// Examples where filePermissions exceed filePermissionsMax:
//
//	filePermissions = "0003" filePermissionsMax = "0644"
//	filePermissions = "0050" filePermissionsMax = "0644"
//	filePermissions = "0700" filePermissionsMax = "0644"
//	filePermissions = "0755" filePermissionsMax = "0644"
func ExceedFilePermissions(filePermissions, filePermissionsMax string) (bool, error) {
	filePermissionsInt, err := strconv.ParseUint(filePermissions, 8, 32)
	if err != nil {
		return false, err
	}
	filePermissionsMaxInt, err := strconv.ParseUint(filePermissionsMax, 8, 32)
	if err != nil {
		return false, err
	}

	fileModePermission := os.FileMode(filePermissionsInt)        // #nosec G115
	fileModePermissionsMax := os.FileMode(filePermissionsMaxInt) // #nosec G115
	return fileModePermission&^fileModePermissionsMax != 0, nil
}

// MatchFileOwnersCases returns []rule.CheckResult for a given file and its owners for a select expected values.
func MatchFileOwnersCases(
	fileStats FileStats,
	expectedFileOwnerUsers,
	expectedFileOwnerGroups []string,
	target rule.Target,
) []rule.CheckResult {
	var checkResults []rule.CheckResult

	if !slices.Contains(expectedFileOwnerUsers, fileStats.UserOwner) {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerUser: %s, expectedOwnerUsers: %v", fileStats.Path, fileStats.UserOwner, expectedFileOwnerUsers))
		checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner user", detailedTarget))
	}

	if !slices.Contains(expectedFileOwnerGroups, fileStats.GroupOwner) {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerGroup: %s, expectedOwnerGroups: %v", fileStats.Path, fileStats.GroupOwner, expectedFileOwnerGroups))
		checkResults = append(checkResults, rule.FailedCheckResult("File has unexpected owner group", detailedTarget))
	}

	if len(checkResults) == 0 {
		detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, ownerUser: %s, ownerGroup: %s", fileStats.Path, fileStats.UserOwner, fileStats.GroupOwner))
		checkResults = append(checkResults, rule.PassedCheckResult("File has expected owners", detailedTarget))
	}

	return checkResults
}
