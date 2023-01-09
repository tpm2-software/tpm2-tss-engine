# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2023-01-09
### Fixed
- Updated minimal version of tpm2-tss to 2.4.x
- Fix encoding of emptyauth
- Fix some memory leaks
- Parent handle issues with signed representation by switching parent handle to BIGNUM.
- Fixed RSA_NO_PADDING modes with OpenSSL 1.1.1
- Fixed autogen (bootstrap) call from release package by embedding VERSION file.

### Added
- Use of restricted keys for signing
- StirRandom
- Run tests using swtpm
- The ability to import key blobs from things like the tpm2-tools project.
- Compatibility with openssl >=1.1.x
- Support for ECDH
- QNX support.
- Only set -Werror for non-release builds.
- Additional checks on TPM responses
- CODE_OF_CONDUCT
- SECURITY reporting instructions

## [1.1.0] - 2020-11-20
### Added
- Configure option for ptpm tests
- Configure script AX_CHECK_ENABLE_DEBUG
- Option for setting tcti on executable
- TCTI-env variable used by default
- Support for parent key passwords
- openssl.cnf sample file

### Changed
- Fix several build system, autotools and testing related issues
  Now adhere to CFLAGS conventions
- Include pkg-config dependecy on libtss2-mu in order to work with tpm2-tss 2.3
- Enables parallel testing of integration tests:
  Make integration tests use TPM simulator; instead of first TPM it finds
  Use of different port numbers for TCP based tests
- Fix EC param info (using named curve format)
- Use tpm2-tools 4.X stable branch for integration tests
- Use libtss2-tctildr.so instead of custom code for tcti setup
- Fix manpages for -P/--parent option and correct engine name
- Fix TCTI env variable handling

## [1.0.0] - 2019-04-04
### Added
- Initial release of the OpenSSL engine for TPM2.0 using the TCG's TPM
  Software Stack compliant tpm2-tss libraries.
- tpm2tss (the engine) compatible against OpenSSL 1.0.2 and 1.1.0.
- tpm2tss-genkey (cli-tool) for creating keys for use with the engine.
- man-pages and bash-completion are included.
