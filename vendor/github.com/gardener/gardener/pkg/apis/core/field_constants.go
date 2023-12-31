// Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

// Field path constants that are specific to the internal API
// representation.
const (
	// BackupBucketSeedName is the field selector path for finding
	// the Seed cluster of a core.gardener.cloud/v1beta1 BackupBucket.
	BackupBucketSeedName = "spec.seedName"
	// BackupEntrySeedName is the field selector path for finding
	// the Seed cluster of a core.gardener.cloud/v1beta1 BackupEntry.
	BackupEntrySeedName = "spec.seedName"
	// BackupEntrySeedName is the field selector path for finding
	// the BackupBucket for a core.gardener.cloud/v1beta1 BackupEntry.
	BackupEntryBucketName = "spec.bucketName"

	// InternalSecretType is the field selector path for finding
	// the secret type of a core.gardener.cloud/v1beta1 InternalSecret.
	InternalSecretType = "type"

	// ProjectNamespace is the field selector path for filtering by namespace
	// for core.gardener.cloud/v1beta1 Project.
	ProjectNamespace = "spec.namespace"

	// RegistrationRefName is the field selector path for finding
	// the ControllerRegistration name of a core.gardener.cloud/{v1alpha1,v1beta1} ControllerInstallation.
	RegistrationRefName = "spec.registrationRef.name"
	// SeedRefName is the field selector path for finding
	// the Seed name of a core.gardener.cloud/{v1alpha1,v1beta1} ControllerInstallation.
	SeedRefName = "spec.seedRef.name"

	// ShootCloudProfileName is the field selector path for finding
	// the CloudProfile name of a core.gardener.cloud/{v1alpha1,v1beta1} Shoot.
	ShootCloudProfileName = "spec.cloudProfileName"
	// ShootSeedName is the field selector path for finding
	// the Seed cluster of a core.gardener.cloud/{v1alpha1,v1beta1} Shoot.
	ShootSeedName = "spec.seedName"
	// ShootStatusSeedName is the field selector path for finding
	// the Seed cluster of a core.gardener.cloud/{v1alpha1,v1beta1} Shoot
	// referred in the status.
	ShootStatusSeedName = "status.seedName"
)
