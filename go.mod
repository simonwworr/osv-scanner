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
