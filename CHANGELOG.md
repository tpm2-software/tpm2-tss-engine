# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc3] - 2019-03-25
### Changed
- Updated INSTALL.md

## [1.0.0-rc2] - 2019-03-25
### Changed
- Bumped minimal required tpm2-tss version to 2.2.2
- Fixes s_client breaking because of interactions between tpm2-tss and openssl.

## [1.0.0-rc1] - 2019-03-04
### Changed
- Dead code removal as reported by coverity.

## [1.0.0_rc0] - 2019-02-21
### Added
- Initial release of the OpenSSL engine for TPM2.0 using the TCG's TPM
  Software Stack compliant tpm2-tss libraries.
- tpm2tss (the engine) compatible against OpenSSL 1.0.2 and 1.1.0.
- tpm2tss-genkey (cli-tool) for creating keys for use with the engine.
- man-pages and bash-completion are included.
