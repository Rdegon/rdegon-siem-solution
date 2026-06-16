# Parallel Batch Correlation Design: 2026-03-26

## Goal

Prepare `batch_corr` for future horizontal scale-out without creating duplicate detections, overlapping interval races, or non-deterministic replay behavior.

## Current Production Position

- `batch_corr` remains single-instance in production
- `stream_corr` and `writer` are the preferred near-term scale-out targets
- the system should not start multiple parallel batch correlators until the ownership model below is implemented

## Safety Requirements

Parallel batch correlation must guarantee:

- deterministic window ownership
- idempotent output writes
- replay-safe reruns
- no duplicate alert creation when adjacent workers touch the same entity/window pair
- bounded overlap for late-arriving events

## Recommended Ownership Model

Partition work by a stable tuple:

- correlation rule id
- normalized window start
- entity partition key

Each worker should own a disjoint partition shard for a bounded lease interval.

Required primitives:

- lease registry with expiry
- durable checkpoint per shard
- output idempotency key derived from `rule_id + window_start + entity_key`
- late-event reconciliation path

## Rollout Plan

1. Keep `batch_corr` single-instance while the partition contract is codified.
2. Introduce shard-planning and idempotency helpers without enabling multi-worker execution.
3. Add duplicate-alert tests with overlapping windows and forced reruns.
4. Enable a shadow second worker that only computes and compares output hashes.
5. Promote to active parallel execution only after shadow parity is stable.

## Near-Term Code Priorities

- keep decomposing runtime helpers away from monolith entry points
- isolate batch-correlation window planning into its own module
- isolate idempotency key generation into reusable helpers
- add deploy smoke that fails on duplicate output for the same shard

## Non-Goals For This Pass

This document does not claim that safe parallel batch correlation is already live.

It exists to keep the next scale-out step disciplined, because uncontrolled parallel `batch_corr` is one of the fastest ways to destroy trust in alert correctness.
