# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1-rc0] - 2019-07-17
### Changed
- Include pkg-config dependecy on libtss2-mu in order to work with tpm2-tss 2.3.
- Use tpm2-tools 3.X stable branch for integration tests.

## [1.0.0] - 2019-04-04
### Added
- Initial release of the OpenSSL engine for TPM2.0 using the TCG's TPM
  Software Stack compliant tpm2-tss libraries.
- tpm2tss (the engine) compatible against OpenSSL 1.0.2 and 1.1.0.
- tpm2tss-genkey (cli-tool) for creating keys for use with the engine.
- man-pages and bash-completion are included.
