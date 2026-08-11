# Performance evidence for AgenticDome integrations

This document explains how to describe performance without turning one test
environment into a universal product claim. It applies to every Python
framework integration.

## What to measure

Run the AgenticDome Performance Harness against the exact tenant runtime
sidecar used by the application. Start with Smoke, then use Baseline, Burst or
Soak only after the lower-risk profile passes.

A publishable report should identify:

- test date and AgenticDome, SDK and sidecar release versions;
- client and sidecar placement and the measured network path;
- profile, duration, concurrency, scheduled and completed requests;
- request and verdict mix across the selected API surfaces;
- p50, p95 and p99 end-to-end latency and error rate;
- whether a value is full request latency or estimated AgenticDome processing
  after network attribution;
- tenant policy and capabilities exercised.

## How to interpret it

End-to-end latency includes DNS, TCP, TLS, connection reuse, proxies, SDK
serialization, payload size, policy work and sidecar capacity. The harness may
estimate the AgenticDome portion by subtracting a measured network baseline;
that remainder is an attribution estimate, not synchronized server-only time.

Compare results only when the target, release, policy, request mix and load
profile are materially equivalent. Keep the original report with the claim so
readers can reproduce and date it.

## Public wording

Use wording such as:

> In the dated attached test, the specified release, tenant policy, sidecar,
> network path and workload produced the reported latency and error rate.

Do not assign fixed latency bands to a policy path or promise a universal p95,
p99 or throughput for every deployment.
