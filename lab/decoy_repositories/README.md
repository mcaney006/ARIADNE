# Decoy repositories

This directory is a generation target, not checked-in data. The lab scenario
script (`lab/scenario_actions/source_code_exfiltration.sh`) creates disposable
decoy git repositories — synthetic "restricted" source files plus honeytokens —
under a temporary directory at runtime and removes them on exit. Nothing here is
a real repository or a real secret.
