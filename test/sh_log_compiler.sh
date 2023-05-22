#!/bin/bash

export LANG=C
export OPENSSL_ENGINES="${OPENSSL_ENGINES:=$PWD/.libs}"
export LD_LIBRARY_PATH="$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}"
export PATH="$PWD:$PATH"

if [ -z "$2" ]; then
    # no device passed
    test_script="$(realpath "$1")"
else
    test_script="$(realpath "$2")"
    INTEGRATION_DEVICE=$1
fi

echo "Creating tpm2tss symlink"
ln -fs libtpm2tss.so .libs/tpm2tss.so

tmp_dir="$(mktemp --directory)"
echo "Switching to temporary directory $tmp_dir"
cd "$tmp_dir"

if [ -z "$INTEGRATION_DEVICE" ]; then
    # No device is passed so the TPM simulator will be used.
    for simulator in 'swtpm' 'tpm_server'; do
        simulator_binary="$(command -v "$simulator")" && break
    done
    if [ -z "$simulator_binary" ]; then
        echo 'ERROR: No TPM simulator was found on PATH'
        exit 99
    fi

    for attempt in $(seq 9 -1 0); do
        simulator_port="$(shuf --input-range 1024-65534 --head-count 1)"
        echo "Starting simulator on port $simulator_port"
        case "$simulator_binary" in
            *swtpm)
                if $simulator_binary socket --print-capabilities --sec-comp; then
                    "$simulator_binary" socket --tpm2 --server port="$simulator_port" \
                                               --ctrl type=tcp,port="$(( simulator_port + 1 ))" \
                                               --flags not-need-init --tpmstate dir="$tmp_dir" \
					       --seccomp "action=none" &
                else
                    "$simulator_binary" socket --tpm2 --server port="$simulator_port" \
                                               --ctrl type=tcp,port="$(( simulator_port + 1 ))" \
                                               --flags not-need-init --tpmstate dir="$tmp_dir" &
                fi;;
            *tpm_server) "$simulator_binary" -port "$simulator_port" &;;
        esac
        simulator_pid="$!"
        sleep 1

        if ( ss --listening --tcp --ipv4 --processes | grep "$simulator_pid" | grep --quiet "$simulator_port" &&
             ss --listening --tcp --ipv4 --processes | grep "$simulator_pid" | grep --quiet "$(( simulator_port + 1 ))" )
        then
            echo "Simulator with PID $simulator_pid started successfully"
            break
        else
            echo "Failed to start simulator, the port might be in use"
            kill "$simulator_pid"

            if [ "$attempt" -eq 0 ]; then
                echo 'ERROR: Reached maximum number of tries to start simulator, giving up'
                exit 99
            fi
        fi
    done

    case "$simulator_binary" in
        *swtpm) export TPM2TSSENGINE_TCTI="swtpm:port=$simulator_port";;
        *tpm_server) export TPM2TSSENGINE_TCTI="mssim:port=$simulator_port";;
    esac
    export TPM2TOOLS_TCTI="$TPM2TSSENGINE_TCTI"

    tpm2_startup --clear
else
    # A physical TPM will be used for the integration test.
    echo "Running the test with $INTEGRATION_DEVICE"
    export TPM2TSSENGINE_TCTI="libtss2-tcti-device.so:$INTEGRATION_DEVICE"
    export TPM2TOOLS_TCTI="$TPM2TSSENGINE_TCTI"
fi

echo "Starting $test_script"
"$test_script"
test_status="$?"

kill "$simulator_pid"
rm -rf "$tmp_dir"

exit "$test_status"
