#!/bin/bash

set -eufx

openssl rand -engine tpm2tss -hex 10 >/dev/null
