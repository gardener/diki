// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"time"
)

func SetTimeNow(f func() time.Time) {
	timeNow = f
}

func GetTimeNow() func() time.Time {
	return timeNow
}

func SetTimeSleep(f func(context.Context, time.Duration) error) {
	timeSleep = f
}

func GetTimeSleep() func(context.Context, time.Duration) error {
	return timeSleep
}
