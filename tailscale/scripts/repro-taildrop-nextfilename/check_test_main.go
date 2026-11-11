package main

import "fmt"

func init() {
	fmt.Println("=== validateBaseName gate ===")
	for _, n := range []string{"x (1) (", "a (5) (", " (0) (", "doc (12) ("} {
		if err := validateBaseName(n); err != nil {
			fmt.Printf("REJECTED %q: %v\n", n, err)
		} else {
			fmt.Printf("ACCEPTED %q (reaches nextFilename)\n", n)
		}
	}
}
