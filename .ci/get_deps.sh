# SPDX-License-Identifier: BSD-2

set -exo pipefail

pushd "$1"

if [ -z "$TPM2TSS_BRANCH" ]; then
    echo "TPM2TSS_BRANCH is unset, please specify TPM2TSS_BRANCH"
    exit 1
fi

if [ -z "$TPM2TOOLS_BRANCH" ]; then
    echo "TPM2TOOLS_BRANCH is unset, please specify TPM2TOOLS_BRANCH"
    exit 1
fi

# Install tpm2-tss
if [ ! -d tpm2-tss ]; then

  git clone --depth=1 -b "${TPM2TSS_BRANCH}" "https://github.com/tpm2-software/tpm2-tss.git"
  pushd tpm2-tss
  ./bootstrap
  ./configure --enable-debug
  make -j$(nproc)
  make install
  popd
else
  echo "tpm2-tss already installed, skipping..."
fi

# Install tpm2-tools
if [ ! -d tpm2-tools ]; then
  git clone --depth=1 -b "${TPM2TOOLS_BRANCH}" "https://github.com/tpm2-software/tpm2-tools.git"
  pushd tpm2-tools
  ./bootstrap
  ./configure --enable-debug --disable-hardening
  make -j$(nproc)
  make install
  popd
else
  echo "tpm2-tss already installed, skipping..."
fi

popd

exit 0
