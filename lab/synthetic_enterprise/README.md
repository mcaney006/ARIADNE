# Synthetic enterprise

The benign background population that scenarios layer their incidents on top of is
generated in code, not stored here. `ariadne.lab.synthetic.SyntheticEnterprise` is
a seeded set of employees and devices that emits logins, processes, repository
clones, DNS lookups, network flows, and sudo activity. `scenarios/*/build.py` use
it so every scenario's `events.jsonl` regenerates deterministically (CI asserts
byte-stability).

This directory is a placeholder for any materialized synthetic-enterprise exports
you choose to generate locally.
