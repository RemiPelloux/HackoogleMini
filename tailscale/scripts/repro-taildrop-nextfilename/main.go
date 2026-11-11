package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// copied verbatim from feature/taildrop/taildrop.go @ v1.104.1
var (
	rxExtensionSuffix = regexp.MustCompile(`(\.[a-zA-Z0-9]{0,3}[a-zA-Z][a-zA-Z0-9]{0,3})*$`)
	rxNumberSuffix    = regexp.MustCompile(` \([0-9]+\)`)
)

func nextFilename(name string) string {
	ext := rxExtensionSuffix.FindString(strings.TrimPrefix(name, "."))
	name = strings.TrimSuffix(name, ext)
	var n uint64
	if rxNumberSuffix.MatchString(name) {
		i := strings.LastIndex(name, " (")
		if n, _ = strconv.ParseUint(name[i+len("( "):len(name)-len(")")], 10, 64); n > 0 {
			name = name[:i]
		}
	}
	return name + " (" + strconv.FormatUint(n+1, 10) + ")" + ext
}

func try(name string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC  nextFilename(%q): %v\n", name, r)
		}
	}()
	out := nextFilename(name)
	fmt.Printf("ok     nextFilename(%q) = %q\n", name, out)
}

func main() {
	for _, n := range []string{"foo.jpg", "Foo (1).jpg", "x (1) (", "a (5) (", " (0) (", "doc (12) ("} {
		try(n)
	}
}
