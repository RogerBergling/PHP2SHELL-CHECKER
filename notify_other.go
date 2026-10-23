//go:build !windows

package main

import (
	"fmt"
	"os"
)

func fatalNotify(title, message string) {
	fmt.Fprintf(os.Stderr, "\n%s: %s\n", title, message)
}
