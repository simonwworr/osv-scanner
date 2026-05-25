// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// osv-scanner checks dependencies against the OSV vulnerability database.
// It scans lock files, SBOMs, and container images for known vulnerabilities.
package main

import (
	"os"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:           "osv-scanner",
		Version:        "1.0.0",
		Usage:          "Scan dependencies for known vulnerabilities using the OSV database",
		UsageText:      "osv-scanner [options] <path> ...",
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "lockfile",
				Aliases: []string{"L"},
				Usage:   "scan a lockfile at the given path",
				Action:  nil,
			},
			&cli.StringSliceFlag{
				Name:    "sbom",
				Aliases: []string{"S"},
				Usage:   "scan a SBOM file (CycloneDX or SPDX) at the given path",
			},
			&cli.StringSliceFlag{
				Name:  "docker",
				Usage: "scan a docker image by name or ID",
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "recursively scan subdirectories for lock files",
			},
			&cli.BoolFlag{
				Name:  "skip-git",
				Usage: "skip scanning git repositories for commit hashes",
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "output format (table, json, sarif, gh-annotations, vertical)",
				Value:   "table",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "write results to this file instead of stdout",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "output results in JSON format (shorthand for --format=json)",
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "disable .osv-scanner-ignore file support",
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "path to a config file to use for filtering",
			},
			&cli.BoolFlag{
				Name:  "experimental-call-analysis",
				Usage: "[EXPERIMENTAL] attempt to perform call analysis on Go and Rust packages",
			},
		},
		Action: func(ctx *cli.Context) error {
			format := ctx.String("format")
			if ctx.Bool("json") {
				format = "json"
			}

			return osvscanner.DoScan(osvscanner.ScannerActions{
				LockfilePaths:        ctx.StringSlice("lockfile"),
				SBOMPaths:            ctx.StringSlice("sbom"),
				DockerContainerNames: ctx.StringSlice("docker"),
				RecursiveDirectories: ctx.Bool("recursive"),
				SkipGit:              ctx.Bool("skip-git"),
				NoIgnore:             ctx.Bool("no-ignore"),
				ConfigOverridePath:   ctx.String("config"),
				DirectoryPaths:       ctx.Args().Slice(),
				Format:               format,
				OutputPath:           ctx.String("output"),
				CallAnalysis:         ctx.Bool("experimental-call-analysis"),
			}, os.Stderr)
		},
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
