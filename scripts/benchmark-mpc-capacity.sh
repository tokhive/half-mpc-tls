#!/usr/bin/env bash
set -euo pipefail

repository_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_dir}/rust"

samples="${TOKENHIVE_BENCH_SAMPLES:-3}"
timeout_seconds="${TOKENHIVE_BENCH_TIMEOUT_SECONDS:-30}"
capacity_bytes="${TOKENHIVE_MPC_BENCH_CAPACITY_BYTES:-4096}"
failed=0

for padding in 512 1536 3072 3500; do
  for sample in $(seq 1 "${samples}"); do
    echo "tokenhive_mpc_benchmark_start padding_bytes=${padding} sample=${sample}"
    if ! timeout --kill-after=2s "${timeout_seconds}s" \
      env TOKENHIVE_MPC_BENCH_PAD_BYTES="${padding}" \
      TOKENHIVE_MPC_BENCH_CAPACITY_BYTES="${capacity_bytes}" \
      cargo test -p tokenhive-sidecar \
        --release \
        attached_channels_run_real_selective_mpc_tls_request \
        -- --ignored --nocapture --test-threads=1; then
      echo "tokenhive_mpc_benchmark_failed padding_bytes=${padding} sample=${sample}" >&2
      failed=1
    fi
  done
done

exit "${failed}"
