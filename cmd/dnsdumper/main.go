package main

import (
	"flag"

	"github.com/rogercoll/dnsdumper"
)

func main() {
	output := flag.String("output", "", "Output: If not defined will be printed through the Stdout")

	dnsdumper.Run("wlp58s0", *output)
}
