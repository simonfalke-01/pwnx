#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
image="pwnx-test-linux:24.04"

docker build \
    --platform linux/amd64 \
    --file "$repository/tests/fixtures/Dockerfile.linux" \
    --tag "$image" \
    "$repository"

docker run --rm \
    --platform linux/amd64 \
    --volume "$repository:/work" \
    --workdir /work \
    --env PYTHONPATH=/work/src \
    "$image" \
    python3 -m pytest "$@"
