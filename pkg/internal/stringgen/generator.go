// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package stringgen

import (
	"math/rand"
	"time"
)

// StringGenerator generates a string with specified length
type StringGenerator interface {
	Generate(int) string
}

// Default returns a new [*RandString] seeded with time.Now().UnixNano()
// and with charset of "1234567890abcdefghijklmnopqrstuvwxyz"
func Default() *RandString {
	chars := []rune("1234567890abcdefghijklmnopqrstuvwxyz")
	return NewRand(rand.NewSource(time.Now().UnixNano()), chars)
}

// RandString is not a secure random generator.
type RandString struct {
	random *rand.Rand
	chars  []rune
}

// NewRand returns a not secure random string generator.
func NewRand(source rand.Source, chars []rune) *RandString {
	return &RandString{
		random: rand.New(source), // #nosec G404
		chars:  chars,
	}
}

// Generate generates a not secure random string with length n.
func (r *RandString) Generate(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = r.chars[r.random.Intn(len(r.chars))]
	}
	return string(runes)
}
