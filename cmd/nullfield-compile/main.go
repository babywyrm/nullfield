package main

import (
	"fmt"
	"io"
	"os"

	"github.com/babywyrm/nullfield/pkg/flow"
)

func main() {
	if err := run(os.Args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) > 2 {
		return fmt.Errorf("usage: %s [agentic-flow.yaml]", args[0])
	}

	var data []byte
	var err error
	if len(args) == 2 {
		data, err = os.ReadFile(args[1])
	} else {
		data, err = io.ReadAll(stdin)
	}
	if err != nil {
		return err
	}

	doc, err := flow.LoadYAML(data)
	if err != nil {
		return err
	}
	artifacts, err := flow.Compile(doc)
	if err != nil {
		return err
	}
	out, err := flow.MarshalArtifactsYAML(artifacts)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}
