// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"math/rand"
	"time"
)

type StringGenerator interface {
	Generate(int) string
}

var (
	chars = []rune("1234567890abcdefghijklmnopqrstuvwxyz")
	// Generator is a not secure random Generator. Exposed for testing purposes.
	Generator = StringGenerator(NewRand(rand.NewSource(time.Now().UnixNano()), chars))
)

// Generate generates a not secure random string with length n.
func (r *RandString) Generate(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = r.chars[r.random.Intn(len(r.chars))]
	}
	return string(runes)
}

// RandString is not a secure random generator.
type RandString struct {
	random *rand.Rand
	chars  []rune
}

// NewRand returns a not secure random string generator.
func NewRand(source rand.Source, chars []rune) *RandString {
	return &RandString{
		random: rand.New(source), //nolint:gosec
		chars:  chars,
	}
}
