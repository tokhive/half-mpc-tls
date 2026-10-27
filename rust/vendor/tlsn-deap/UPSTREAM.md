# Upstream provenance

- Repository: `https://github.com/tlsnotary/tlsn`
- Upstream commit: `47aee45b53e06648c1b2ad3689b367b8c923fdec`
- Upstream path: `crates/components/deap`
- Imported: 2026-08-26

TokenHive keeps this controlled fork to expose a narrow accessor for the
online MPC VM. The Hub uses it to schedule asymmetric server-traffic-key
decoding without also scheduling disclosure in the post-session ZK VM.
