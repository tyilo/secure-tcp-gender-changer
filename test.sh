#!/bin/bash
set -euo pipefail

PROXY_PORT=1234
INCOMING_PORT=5678

jobs=()
trap '((${#jobs[@]} == 0)) || kill $jobs' EXIT HUP TERM INT

#cargo run generate
cargo run server \
	--proxy-port "$PROXY_PORT" \
	--incoming-port "$INCOMING_PORT" \
	--server-cert certs/server_cert.der \
	--server-private-key certs/server_key.der \
	--client-cert certs/client_cert.der &
jobs+=($!)

sleep 1

cargo run client \
	--outgoing-host example.org:443 \
	--proxy-host localhost:"$PROXY_PORT" \
	--client-cert certs/client_cert.der \
	--client-private-key certs/client_key.der \
	--server-cert certs/server_cert.der &
jobs+=($!)

sleep 1

curl --fail -v "https://example.org:$INCOMING_PORT/" --resolve "example.org:$INCOMING_PORT:127.0.0.1"
