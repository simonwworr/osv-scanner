// Package osvscanner provides the core scanning functionality for detecting
// open source vulnerabilities in project dependencies.
package osvscanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

// ScannerActions defines the configuration options for a vulnerability scan.
type ScannerActions struct {
	// LockfilePaths is a list of explicit lockfile paths to scan.
	LockfilePaths []string
	// SBOMPaths is a list of SBOM file paths to scan.
	SBOMPaths []string
	// DirectoryPaths is a list of directories to recursively scan for lockfiles.
	DirectoryPaths []string
	// SkipGit controls whether git history scanning is skipped.
	SkipGit bool
	// Recursive enables recursive directory scanning.
	Recursive bool
	// NoIgnore disables .gitignore and .osvignore filtering.
	NoIgnore bool
	// JSONOutput enables JSON-formatted output.
	JSONOutput bool
	// ExperimentalCallAnalysis enables experimental call graph analysis.
	ExperimentalCallAnalysis bool
}

// ErrVulnerabilitiesFound is returned when one or more vulnerabilities are detected.
var ErrVulnerabilitiesFound = errors.New("vulnerabilities found")

// ErrNoPackagesFound is returned when no packages could be extracted from the inputs.
var ErrNoPackagesFound = errors.New("no packages found to scan")

// DoScan performs a vulnerability scan based on the provided ScannerActions
// and returns the vulnerability results or an error.
func DoScan(actions ScannerActions, outputter models.Reporter) (models.VulnerabilityResults, error) {
	if outputter == nil {
		return models.VulnerabilityResults{}, fmt.Errorf("reporter must not be nil")
	}

	packages := []*models.PackageInfo{}

	// Process explicit lockfile paths
	for _, path := range actions.LockfilePaths {
		pkgs, err := extractPackagesFromLockfile(path)
		if err != nil {
			outputter.PrintErrorf("Failed to parse lockfile %q: %v\n", path, err)
			continue
		}
		packages = append(packages, pkgs...)
	}

	// Process directory paths
	for _, dir := range actions.DirectoryPaths {
		pkgs, err := scanDirectory(dir, actions.Recursive)
		if err != nil {
			outputter.PrintErrorf("Failed to scan directory %q: %v\n", dir, err)
			continue
		}
		packages = append(packages, pkgs...)
	}

	if len(packages) == 0 {
		return models.VulnerabilityResults{}, ErrNoPackagesFound
	}

	// Query the OSV API for vulnerabilities
	results, err := osv.MakeRequest(osv.BatchedQuery{
		Queries: buildOSVQueries(packages),
	})
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("querying OSV API: %w", err)
	}

	vulnResults := models.VulnerabilityResults{
		Results: groupResultsBySource(packages, results),
	}

	if vulnResults.HasVulnerabilities() {
		return vulnResults, ErrVulnerabilitiesFound
	}

	return vulnResults, nil
}

// extractPackagesFromLockfile parses a lockfile at the given path and returns
// the list of packages it contains.
func extractPackagesFromLockfile(path string) ([]*models.PackageInfo, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("lockfile not found: %w", err)
	}

	parsed, err := lockfile.Parse(path, "")
	if err != nil {
		return nil, err
	}

	pkgs := make([]*models.PackageInfo, 0, len(parsed.Packages))
	for i := range parsed.Packages {
		pkgs = append(pkgs, &models.PackageInfo{
			Name:      parsed.Packages[i].Name,
			Version:   parsed.Packages[i].Version,
			Ecosystem: parsed.Packages[i].Ecosystem,
			Source:    models.SourceInfo{Path: path, Type: "lockfile"},
		})
	}

	return pkgs, nil
}

// scanDirectory walks the given directory and extracts packages from any
// recognized lockfiles found within it.
func scanDirectory(dir string, recursive bool) ([]*models.PackageInfo, error) {
	var packages []*models.PackageInfo

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && !recursive && path != dir {
			return filepath.SkipDir
		}
		if !d.IsDir() && lockfile.IsKnownLockfile(path) {
			pkgs, parseErr := extractPackagesFromLockfile(path)
			if parseErr == nil {
				packages = append(packages, pkgs...)
			}
		}
		return nil
	})

	return packages, err
}

// buildOSVQueries constructs a slice of OSV API queries from the given packages.
func buildOSVQueries(packages []*models.PackageInfo) []*osv.Query {
	queries := make([]*osv.Query, 0, len(packages))
	for _, pkg := range packages {
		queries = append(queries, &osv.Query{
			Package: osv.Package{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem,
			},
			Version: pkg.Version,
		})
	}
	return queries
}

// groupResultsBySource organises OSV API results back to their originating
// source file for structured reporting.
func groupResultsBySource(packages []*models.PackageInfo, response *osv.BatchedResponse) []models.PackageSource {
	sourceMap := map[string]*models.PackageSource{}

	for i, result := range response.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]
		key := pkg.Source.Path

		if _, ok := sourceMap[key]; !ok {
			sourceMap[key] = &models.PackageSource{Source: pkg.Source}
		}

		sourceMap[key].Packages = append(sourceMap[key].Packages, models.PackageVulns{
			Package:         *pkg,
			Vulnerabilities: result.Vulns,
		})
	}

	sources := make([]models.PackageSource, 0, len(sourceMap))
	for _, src := range sourceMap {
		sources = append(sources, *src)
	}
	return sources
}
