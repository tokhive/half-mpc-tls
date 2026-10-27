#!/usr/bin/env bash
set -euo pipefail

repository_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_dir}/rust"

samples="${TOKENHIVE_BENCH_SAMPLES:-1}"
timeout_seconds="${TOKENHIVE_BENCH_TIMEOUT_SECONDS:-900}"
sizes="${TOKENHIVE_BENCH_SIZES:-65536 262144 1048576 5242880}"
failed=0

for capacity in ${sizes}; do
  # Leave room for the fixed JSON and canonical HTTP/1.1 headers.
  padding=$((capacity - 1024))
  for sample in $(seq 1 "${samples}"); do
    echo "tokenhive_mpc_large_benchmark_start capacity_bytes=${capacity} padding_bytes=${padding} sample=${sample}"
    if ! /usr/bin/time -f \
      "tokenhive_mpc_benchmark_resources elapsed_seconds=%e peak_rss_kib=%M cpu_percent=%P" \
      timeout --kill-after=5s "${timeout_seconds}s" \
      env TOKENHIVE_MPC_TEST_PUBLIC_BODY=1 \
      TOKENHIVE_MPC_BENCH_CAPACITY_BYTES="${capacity}" \
      TOKENHIVE_MPC_BENCH_PAD_BYTES="${padding}" \
      cargo test -p tokenhive-sidecar \
        --release \
        attached_channels_run_real_selective_mpc_tls_request \
        -- --ignored --nocapture --test-threads=1; then
      echo "tokenhive_mpc_large_benchmark_failed capacity_bytes=${capacity} sample=${sample}" >&2
      failed=1
    fi
  done
done

exit "${failed}"
