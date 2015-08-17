package main

import "fmt"

func debug(prefix string, a ...interface{}) {
	if logDebug {
		params := []interface{}{prefix}
		params = append(params, a...)

		fmt.Println(params...)
	}
}
