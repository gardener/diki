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
				podExecutorRootPath,
				podExecutor,
				pod,
				container.Name,
				baseContainerID,
				excludeSources,
			)
			if err2 != nil {
				err = errors.Join(err, err2)
			}

			if len(containerStats) > 0 {
				stats[container.Name] = containerStats
			}
		default:
			err = errors.Join(err, fmt.Errorf("cannot handle container with Name %s", container.Name))
		}
	}
	return stats, err
}

func getContainerMountedFileStatResults(
	ctx context.Context,
	podExecutorRootPath string,
	podExecutor pod.PodExecutor,
	pod corev1.Pod,
	containerName, containerID string,
	excludedSources []string,
) ([]FileStats, error) {
	stats := []FileStats{}
	var err error

	commandResult, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`%s/usr/local/bin/nerdctl --namespace k8s.io inspect --mode=native %s | jq -r .[0].Spec.mounts`, podExecutorRootPath, containerID))
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
			delimiter := "\t"
			mountStats, err2 := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -type f -exec stat -Lc "%%a%[2]s%%u%[2]s%%g%[2]s%%F%[2]s%%n" {} \;`, mount.Source, delimiter))

			if err2 != nil {
				err = errors.Join(err, err2)
				continue
			}

			if len(mountStats) == 0 {
				fileNum, err2 := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`ls %s | wc -l`, mount.Source))
				if err2 != nil {
					err = errors.Join(err, err2)
					continue
				}

				if fileNum != "0\n" {
					err = errors.Join(err, fmt.Errorf("could not find files in %s", mount.Source))
				}
				continue
			}

			mountStatsSlice := strings.Split(strings.TrimSpace(mountStats), "\n")
			for _, mountStats := range mountStatsSlice {
				mountStatsFile, err2 := NewFileStats(mountStats, delimiter)
				if err2 != nil {
					err = errors.Join(err, err2)
					continue
				}

				stats = append(stats, mountStatsFile)
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

// ExceedFilePermissions returns true if any of the user, group or other permissions
// exceed their counterparts in what is passed as max permissions.
//
// Examples where filePermissions do not exceed filePermissionsMax:
//
//	filePermissions = "0003" filePermissionsMax = "0644"
//	filePermissions = "0444" filePermissionsMax = "0644"
//	filePermissions = "0600" filePermissionsMax = "0644"
//	filePermissions = "0644" filePermissionsMax = "0644"
//
// Examples where filePermissions exceed filePermissionsMax:
//
//	filePermissions = "0005" filePermissionsMax = "0644"
//	filePermissions = "0050" filePermissionsMax = "0644"
//	filePermissions = "0700" filePermissionsMax = "0644"
//	filePermissions = "0755" filePermissionsMax = "0644"
func ExceedFilePermissions(filePermissions, filePermissionsMax string) (bool, error) {
	filePermissionsInt, err := strconv.ParseInt(filePermissions, 8, 32)
	if err != nil {
		return false, err
	}
	filePermissionsMaxInt, err := strconv.ParseInt(filePermissionsMax, 8, 32)
	if err != nil {
		return false, err
	}

	fileModePermission := os.FileMode(filePermissionsInt)
	fileModePermissionsMax := os.FileMode(filePermissionsMaxInt)
	return fileModePermission&^fileModePermissionsMax != 0, nil
}

// MatchFileOwnersCases returns []rule.CheckResult for a given file and its owners for a select expected values.
func MatchFileOwnersCases(
	fileStats FileStats,
	expectedFileOwnerUsers,
	expectedFileOwnerGroups []string,
	target rule.Target,
) []rule.CheckResult {
	checkResults := []rule.CheckResult{}

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
