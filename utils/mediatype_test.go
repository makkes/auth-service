package utils

import (
	"fmt"
	"testing"

	"github.com/justsocialapps/assert"
)

func TestEqualTypesShouldMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("application", "json")
	m2 := NewMediaType("application", "json")
	assert.True(m1.Matches(m2), "Media types should match")
	assert.True(m2.Matches(m1), "Media types should match")
}

func TestWildcardTypeShouldMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("*", "json")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), fmt.Sprintf("%s should not match %s", m1, m2))
	assert.True(m2.Matches(m1), fmt.Sprintf("%s should match %s", m2, m1))
}

func TestWildcardSubtypeShouldMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("application", "*")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), fmt.Sprintf("%s should not match %s", m1, m2))
	assert.True(m2.Matches(m1), "Media types should match")
}

func TestWildcardMediaTypeShouldMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("*", "*")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), fmt.Sprintf("%s should not match %s", m1, m2))
	assert.True(m2.Matches(m1), "Media types should match")
}

func TestMixedWildcardsShouldNotMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("*", "json")
	m2 := NewMediaType("application", "*")
	assert.False(m1.Matches(m2), "Media types should not match")
	assert.False(m2.Matches(m1), "Media types should not match")
}

func TestTypesShouldNotMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("text", "plain")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), "Media types should not match")
	assert.False(m2.Matches(m1), "Media types should not match")
}

func TestWildcardTypesShouldNotMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("*", "plain")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), "Media types should not match")
	assert.False(m2.Matches(m1), "Media types should not match")
}

func TestWildcardSubtypesShouldNotMatch(t *testing.T) {
	assert := assert.NewAssert(t)

	m1 := NewMediaType("text", "*")
	m2 := NewMediaType("application", "json")
	assert.False(m1.Matches(m2), "Media types should not match")
	assert.False(m2.Matches(m1), "Media types should not match")
}

func TestParseAcceptHeaderShouldFailWithEmptyHeader(t *testing.T) {
	assert := assert.NewAssert(t)

	_, err := ParseAcceptHeader("")
	assert.NotNil(err, "Error is nil but should not be")
}

func TestParseAcceptHeaderShouldHandleUnknownMediaType(t *testing.T) {
	assert := assert.NewAssert(t)

	mt, err := ParseAcceptHeader("this/doesnotexist")
	assert.Nil(err, "Error is nil but should not be")
	assert.Equal(len(mt), 1, "Got an unexpected number of media types")
	assert.Equal(mt[0].Type, "this", "Type is wrong")
	assert.Equal(mt[0].Subtype, "doesnotexist", "Subtype is wrong")
}
