package main

import (
	"errors"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidFileName = errors.New("invalid filename")

func validFilenameRune(r rune) bool {
	switch r {
	case '/':
		return false
	case '\\', ':', '*', '"', '<', '>', '|':
		return false
	}
	return unicode.IsGraphic(r)
}
func isPartialOrDeleted(s string) bool {
	return strings.HasSuffix(s, ".deleted") || strings.HasSuffix(s, ".partial")
}

// verbatim from taildrop.go validateBaseName @ v1.104.1
func validateBaseName(name string) error {
	if !utf8.ValidString(name) || strings.TrimSpace(name) != name || len(name) > 255 {
		return ErrInvalidFileName
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." {
		return ErrInvalidFileName
	}
	if isPartialOrDeleted(name) {
		return ErrInvalidFileName
	}
	for _, r := range name {
		if !validFilenameRune(r) {
			return ErrInvalidFileName
		}
	}
	if !filepath.IsLocal(name) {
		return ErrInvalidFileName
	}
	return nil
}
