# Dependencies

## GNU/Linux
* GNU Autoconf
* GNU Autoconf Archive
* GNU Automake
* GNU Libtool
* C compiler
* C library development libraries and header files
* pkg-config
* OpenSSL >= 1.0.2
* tpm2-tss >= 2.4.x
* pandoc
* doxygen

Integration tests also require:
* expect
* tpm2-tools 4.0 (or 4.X branch)
* [swtpm](https://github.com/stefanberger/swtpm) or [tpm_server](https://sourceforge.net/projects/ibmswtpm2/)
* realpath
* ss

## Ubuntu
```
sudo apt -y install \
  build-essential \
  autoconf \
  autoconf-archive \
  automake \
  m4 \
  libtool \
  gcc \
  pkg-config \
  libssl-dev \
  pandoc \
  doxygen

git clone --depth=1 http://www.github.com/tpm2-software/tpm2-tss
cd tpm2-tss
./bootstrap
./configure
make -j$(nproc)
sudo make install
```

Integration tests:
```
sudo apt -y install  \
  expect \
  realpath \
  ss

git clone --depth=1 http://github.com/tpm2-software/tpm2-tools
cd tpm2-tools
./bootstrap
./configure
make -j$(nproc)
sudo make install

wget https://download.01.org/tpm2/ibmtpm974.tar.gz
mkdir ibmtpm
tar axf ibmtpm974.tar.gz -C ibmtpm
make -C ibmtpm/src -j$(nproc)
sudo cp ibmtpm/src/tpm_server /usr/local/bin
```

# Building from source
```
git clone --depth=1 http://www.github.com/tpm2-software/tpm2-tss-engine
./bootstrap
./configure
make -j$(nproc)
sudo make install
```

# Configuration options
You may pass the following options to `./configure`

## Debug messages
This option will enable a lot of debug printing during the invocation of the
library:
```
./configure --enable-debug
```

## Developer linking
In order to link against a developer version of tpm2-tss (not installed):
```
./configure \
  PKG_CONFIG_PATH=${TPM2TSS}/lib:$PKG_CONFIG_PATH \
  CFLAGS=-I${TPM2TSS}/include \
  LDFLAGS=-L${TPM2TSS}/src/tss2-{tcti,mu,sys,esys}/.libs 
```

## Testing
In order to build the tests, pass the following options
(see the additional dependencies above):
```
./configure --enable-integration --enable-unit
make check
```

# Post installation

## ldconfig
You may need to run ldconfig after `make install` to update runtime bindings:
```
sudo ldconfig
```
