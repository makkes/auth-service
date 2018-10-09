package utils

import (
	"mime"
	"strings"

	"github.com/pkg/errors"
)

type MediaType struct {
	Type       string
	Subtype    string
	Parameters map[string]string
}

var WildcardMediaType = MediaType{"*", "*", nil}

func NewMediaType(typ, subtype string) MediaType {
	return MediaType{
		Type:    typ,
		Subtype: subtype,
	}
}

func (m MediaType) Matches(accept MediaType) bool {
	typeMatches := accept.Type == "*" || accept.Type == m.Type
	subtypeMatches := accept.Subtype == "*" || accept.Subtype == m.Subtype
	return typeMatches && subtypeMatches
}

func ParseMediaType(in string) (*MediaType, error) {
	rawType, params, err := mime.ParseMediaType(in)
	if err != nil {
		return nil, errors.Wrap(err, "Could not parse media type")
	}
	typeArr := strings.SplitN(rawType, "/", 2)
	return &MediaType{
		Type:       typeArr[0],
		Subtype:    typeArr[1],
		Parameters: params,
	}, nil
}

func ParseAcceptHeader(h string) ([]MediaType, error) {
	parts := strings.Split(h, ",")
	res := make([]MediaType, 0)
	for _, part := range parts {
		mediaType, err := ParseMediaType(part)
		if err != nil {
			return nil, errors.Wrap(err, "Could not parse accept header")
		}
		res = append(res, *mediaType)
	}
	return res, nil
}
