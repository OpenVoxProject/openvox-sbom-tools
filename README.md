OpenVox SBOM Tools
==================

This repository contains tooling for generating and manipulating
Software Bill of Materials (SBOMs) for various OpenVox projects.

This tooling automates the following workflows:

  - Maintenance of data files containing information on software
    components included in OpenVox packages.

  - Generation of Software Bill of Materials (SBOMs), in CycloneDX-JSON
    format, from data files.

  - Generation of CVE information from SBOMs.

> [!NOTE]
>
> Currently, this project only covers the `openvox-agent` and `openbolt`
> packages, and only package versions released in 2026. Support for
> `openvox-server` and `openvoxdb` is planned.

## Installation

This project is set up to use Mise for managing depedencies.
First, install `mise` using your method of choice:

  https://mise.jdx.dev/installing-mise.html

Then, execute the following commands in a clone of this repository:

```sh
mise trust
mise up
```

Dependencies can be kept up to date by periodically running `mise up`.

> [!NOTE]
>
> If you prefer not to use `mise`, then review the `mise.toml` file
> and install everything listed in the `[tools]` section. Use `rake`
> instead of `mise rake` when following steps in this README.

## CVE Reporting Workflows

The following rake tasks can be used to generate Markdown-formatted
tables of CVEs reported against software components in a package
release. This is done by feeding SBOM data stored in
[`lib/openvox/sbom-tools/sbom`][sbom-data] to the [Grype scanner][grype].


[sbom-data]: lib/openvox/sbom-tools/sbom
[grype]: https://github.com/anchore/grype

Reports of CVEs affecting a release can be generated with the
`vox:sbom:cves` task:

```console
$ mise rake vox:sbom:cves[openvox-agent,8.27.0]

| Identifier          | CVSS 3.1 Score | Affects                           |
| :------------------ | :------------: | :-------------------------------- |
| GHSA-h8w8-99g7-qmvj |       N/A      | pkg:gem/concurrent-ruby@1.3.6     |
| GHSA-6wx8-w4f5-wwcr |       N/A      | pkg:gem/concurrent-ruby@1.3.6     |
| GHSA-wv3x-4vxv-whpp |       N/A      | pkg:gem/concurrent-ruby@1.3.6     |
| GHSA-46q3-7gv7-qmgg |       N/A      | pkg:gem/net-imap@0.4.24           |
| GHSA-8p34-64r3-mwg8 |       N/A      | pkg:gem/net-imap@0.4.24           |
| GHSA-c4fp-cxrr-mj66 |       N/A      | pkg:gem/net-imap@0.4.24           |
| CVE-2026-34182      |       9.1      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-45447      |       8.8      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-7383       |       8.1      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-34180      |       7.5      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-45445      |       7.5      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-9076       |       7.5      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-42766      |       5.9      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-42767      |       5.9      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-45446      |       4.8      | pkg:github/openssl/openssl@3.0.20 |
| CVE-2026-42770      |       3.7      | pkg:github/openssl/openssl@3.0.20 |
```

And a report of CVEs fixed between two releases can be generated with
the `vox:sbom:cves_fixed` task:

```console
$ mise rake vox:sbom:cves_fixed[openvox-agent,8.27.0,8.28.0]

| Identifier     | CVSS 3.1 Score | Resolved By                       |
| :------------- | :------------: | :-------------------------------- |
| CVE-2026-34182 |       9.1      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-45447 |       8.8      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-7383  |       8.1      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-34180 |       7.5      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-45445 |       7.5      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-9076  |       7.5      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-42766 |       5.9      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-42767 |       5.9      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-45446 |       4.8      | pkg:github/openssl/openssl@3.0.21 |
| CVE-2026-42770 |       3.7      | pkg:github/openssl/openssl@3.0.21 |
```

The `vox:sbom:cves` and `vox:sbom:cves_fixed` tasks accept an optional
`linkify` argument that includes links to CVE reports in the generated
Markdown. This behavior is useful for generating `CHANGELOG.md` entries
but is off by default as it is less readable as terminal output:

```console
$ mise rake vox:sbom:cves_fixed[openvox-agent,8.27.0,8.28.0,true]

| Identifier                                                        | CVSS 3.1 Score | Resolved By                         |
| :---------------------------------------------------------------- | :------------: | :---------------------------------- |
| [CVE-2026-34182](https://nvd.nist.gov/vuln/detail/CVE-2026-34182) |       9.1      | `pkg:github/openssl/openssl@3.0.21` |
| [CVE-2026-45447](https://nvd.nist.gov/vuln/detail/CVE-2026-45447) |       8.8      | `pkg:github/openssl/openssl@3.0.21` |
...output truncated for brevity
```

## Component Reporting Workflows

The following rake tasks can be used to generate Markdown-formatted
tables of Components included in a package release. These reports
are generated from the [`components` section][cdx-components] of
SBOM files stored in [`lib/openvox/sbom-tools/sbom`][sbom-data].

[cdx-components]: https://cyclonedx.org/docs/1.7/json/#components

A table of all components in a release can be generated with the
`vox:sbom:components` task:

```console
$ mise rake vox:sbom:components[openbolt,5.6.0]

| Component                           | Version         |
| :---------------------------------- | :-------------- |
| openbolt                            | 5.6.0           |
| openbolt-runtime                    | 2026.06.10.1    |
| pkg:gem/CFPropertyList              | 4.0.0           |
| pkg:gem/abbrev                      | 0.1.1           |
| pkg:gem/addressable                 | 2.9.0           |
| pkg:gem/aws-eventstream             | 1.4.0           |
| pkg:gem/aws-partitions              | 1.1259.0        |
| pkg:gem/aws-sdk-core                | 3.251.0         |
...output truncated for brevity
```

A table of all components that changed between two releases can be
generated with the `vox:sbom:component_diff` task:

```console
# OpenVox 9.x branched off after the 8.26.2 release.
$ mise rake vox:sbom:component_diff[openvox-agent,8.26.2,9.0.0-alpha2]

| Component                   | Old Version     | New Version |
| :-------------------------- | :-------------- | :---------- |
| openfact                    | 5.6.0           | 5.6.1       |
| pkg:gem/abbrev              | 0.1.1           | 0.1.2       |
| pkg:gem/benchmark           | 0.2.1           | 0.5.0       |
| pkg:gem/bigdecimal          | 3.1.3           | 4.0.1       |
| pkg:gem/bundler             | 2.4.19          | 4.0.10      |
| pkg:gem/cgi                 | 0.3.7           | Removed     |
...output truncated for brevity
```

## SBOM Generation Workflows

SBOMs in [CycloneDX-JSON format][cdx-json] can be generated using
the `vox:sbom:gen` task:

[cdx-json]: https://cyclonedx.org/specification/overview/

```console
$ mise rake vox:sbom:gen[openbolt,5.3.0]
[bundle-install] sources up-to-date, skipping
[rake] $ rake vox:sbom:gen[openbolt,5.3.0]
Generating SBOM: /home/sharpie/distrobox/tools-44/Projects/OpenVox/openvox-sbom-tools/lib/openvox/sbom-tools/sbom/openbolt_5.3.0.cdx.json
Finished in 268.4ms
```

> [!NOTE]
>
> The generation task will not over-write existing files in
> [`lib/openvox/sbom-tools/sbom`][sbom-data]. To update existing SBOMs,
> remove the output files before running the `vox:sbom:gen` task.

## Data Update Workflows

A variety of inputs are used to generate SBOM files. These inputs can
be refreshed using the `vox:sbom:update_data` task.

This task will sync data from the following sources:

  - Lists of Gems included by upstream Ruby sourced from https://stdgems.org:
    https://github.com/janlelis/stdgems

  - Lists of Platforms for which OpenVox packages are built, sourced from:
    https://github.com/OpenVoxProject/shared-actions/blob/main/platforms.json

  - Lists of components included in OpenVox packages, sourced by running
    `vanagon inspect` on each tag in the following repositories:

      * https://github.com/OpenVoxProject/puppet-runtime/
      * https://github.com/OpenVoxProject/openvox/tree/main/packaging
      * https://github.com/OpenVoxProject/openbolt/tree/main/packaging

## License

Different pieces of content in this project are available under different license terms:

  - See [lib/openvox/sbom-tools/data/COPYING](lib/openvox/sbom-tools/data/COPYING) for licenses that apply to data files in the `lib/openvox/sbom-tools/data/` directory.

  - Data files in the `lib/openvox/sbom-tools/sbom/` directory are available under the Creative Commons Attribution 4.0 International license. See [lib/openvox/sbom-tools/sbom/LICENSE](lib/openvox/sbom-tools/sbom/LICENSE) for terms.

  - [lib/openvox/sbom-tools/markdown-tables.rb](lib/openvox/sbom-tools/markdown-tables.rb) is Copyright (c) 2017 Chris de Graaf and uses the MIT license.

  - Everything else is released under the AGPL as described in [LICENSE](LICENSE)
