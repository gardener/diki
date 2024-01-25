package fake

import "github.com/gardener/diki/pkg/internal/stringgen"

var _ stringgen.StringGenerator = (*FakeRandString)(nil)

// Generate returns the same rune n times
func (r *FakeRandString) Generate(n int) string {
	b := make([]rune, n)
	for i := 0; i < n; i++ {
		b[i] = r.Rune
	}
	r.Rune++
	return string(b)
}

// FakeRandString is a generator that satisfies [stringgen.StringGenerator]
type FakeRandString struct {
	Rune rune
}
