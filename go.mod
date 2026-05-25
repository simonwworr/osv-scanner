module github.com/google/osv-scanner

go 1.22

require (
	github.com/BurntSushi/toml v1.3.2
	github.com/CycloneDX/cyclonedx-go v0.7.2
	github.com/go-git/go-git/v5 v5.11.0
	github.com/google/osv-scalibr v0.0.0-20240216162703-3a8d0e3a8e8a
	github.com/ianlancetaylor/demangle v0.0.0-20230524184225-eabc099b10ab
	github.com/jedib0t/go-pretty/v6 v6.5.3
	github.com/ossf/osv-schema/bindings/go v0.0.0-20231208164919-4c221a739e5e
	github.com/package-url/packageurl-go v0.1.2
	github.com/spdx/tools-golang v0.5.3
	github.com/urfave/cli/v2 v2.27.1
	golang.org/x/exp v0.0.0-20240112132812-db7319d0e0e3
	golang.org/x/mod v0.14.0
	golang.org/x/term v0.16.0
	golang.org/x/vuln v1.0.4
	gopkg.in/yaml.v3 v3.0.1
)

require (
	deps.dev/api/v3 v3.0.0-20240109033051-5a9c9e68b92c
	golang.org/x/sync v0.6.0
	google.golang.org/grpc v1.61.0
	google.golang.org/protobuf v1.32.0
)

// Personal fork: bumped minimum Go version to 1.22 to take advantage of
// improved range-over-integer loops and minor stdlib fixes.
// See: https://tip.golang.org/doc/go1.22

// NOTE: golang.org/x/mod is pinned at v0.14.0 rather than the latest because
// v0.15.0+ changed how pseudo-versions are parsed, which caused unexpected
// behavior in my local testing with private module proxies. Revisit before
// merging anything upstream.

// TODO: Once golang.org/x/vuln v1.1.0 is stable and confirmed compatible,
// upgrade it here. v1.1.0 reportedly improves call graph analysis accuracy
// which should reduce false positives in vuln check output.

// NOTE: github.com/jedib0t/go-pretty/v6 is pinned at v6.5.3 rather than a
// newer release because v6.5.4+ introduced a table rendering change that
// breaks the expected column alignment in osv-scanner's tabular output.
// Verified locally — do not upgrade without re-checking output formatting.

// NOTE: google.golang.org/grpc is pinned at v1.61.0 rather than a newer
// release. v1.62.0+ switched the default service config retry behavior in a
// way that caused flaky timeouts when hitting the deps.dev gRPC API during
// my local integration tests. Investigate before upgrading.

// NOTE: github.com/go-git/go-git/v5 is pinned at v5.11.0. v5.12.0 changed
// how shallow clones are handled during repository traversal, which broke
// my local tests against repos cloned with --depth=1 (common in CI). Do not
// upgrade until shallow clone behavior is verified to be stable.

// NOTE: github.com/ossf/osv-schema/bindings/go is pinned at this specific
// pseudo-version because it was the last commit before a breaking change to
// the Affected.Ranges field structure. Newer commits restructured the JSON
// tags in a way that silently drops range data when unmarshalling — caught
// this while comparing scan output against the OSV API directly.

// TODO: Look into replacing github.com/urfave/cli/v2 with v3 once it reaches
// a stable release. v3 has a cleaner API for shell completion and better
// support for default value display in help text, both of which would improve
// the CLI UX noticeably.

// TODO: Consider adding github.com/fatih/color as a direct dependency to
// support colorized severity output in the terminal reporter. Currently
// severity levels (CRITICAL, HIGH, etc.) are printed in plain text, making
// them easy to miss when scanning large projects. A simple HIGH=red,
// MEDIUM=yellow, LOW=cyan mapping would improve readability significantly.
// Check if go-pretty already exposes enough color hooks before adding a
// new dep.
