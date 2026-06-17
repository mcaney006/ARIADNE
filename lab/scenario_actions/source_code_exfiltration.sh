#!/usr/bin/env bash
#
# Source-code exfiltration scenario — REAL benign activity against disposable
# decoys, not a replayed fixture. The script:
#
#   1. creates several decoy git repositories with synthetic "restricted" files
#      and honeytokens,
#   2. creates a staging directory standing in for removable media,
#   3. clones the repos with actual git, greps for credential-pattern files,
#      builds an archive (gpg if available, else tar), copies it to staging,
#   4. writes and deletes a throwaway shell-history file and drops a
#      "telemetry stopped" marker,
#   5. records every action to actions.jsonl,
#   6. turns those actions into normalized events and replays them through the
#      real detection pack, asserting the case opens.
#
# Everything stays local and is cleaned up on exit. No real credentials, no
# external services, no network egress.
#
# Usage:  bash lab/scenario_actions/source_code_exfiltration.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$(mktemp -d)"
ACTIONS="${LAB}/actions.jsonl"
STAGING="${LAB}/removable_media"
WORK="${LAB}/work"
ACTOR="lab-user"
DEVICE="LAB-WS-01"

cleanup() { rm -rf "${LAB}"; }
trap cleanup EXIT

now() { date +%s; }
record() { printf '%s\n' "$1" >> "${ACTIONS}"; }

echo "[lab] workspace: ${LAB}"
mkdir -p "${STAGING}" "${WORK}"

echo "[lab] creating decoy repositories with synthetic restricted files + honeytokens"
ORIGINS="${LAB}/origins"
mkdir -p "${ORIGINS}"
for i in $(seq -w 1 10); do
  REPO="${ORIGINS}/restricted-proj-${i}"
  git init -q --bare "${REPO}.git"
  SEED="${LAB}/seed-${i}"
  git init -q "${SEED}"
  ( cd "${SEED}"
    git config user.email lab@example.invalid
    git config user.name "Lab Seeder"
    git config commit.gpgsign false
    git config tag.gpgsign false
    printf 'AKIA%012dHONEYTOKEN\n' "${i#0}" > credentials.env
    echo "-----BEGIN FAKE KEY-----" > deploy.pem
    echo "synthetic restricted source ${i}" > main.py
    git add -A && git commit -q -m "seed restricted project ${i}"
    git remote add origin "${REPO}.git"
    git push -q origin HEAD:master 2>/dev/null || git push -q origin HEAD:main
  )
done

echo "[lab] cloning restricted repositories (real git)"
for i in $(seq -w 1 10); do
  git clone -q "${ORIGINS}/restricted-proj-${i}.git" "${WORK}/proj-${i}"
  record "{\"kind\":\"clone\",\"ts\":$(now),\"repo\":\"restricted/proj-${i}\"}"
  sleep 0.1
done

echo "[lab] searching for credential-pattern files"
grep -rIl -E 'AKIA|BEGIN .*KEY|\.env' "${WORK}" >/dev/null || true

echo "[lab] building an encrypted archive"
ARCHIVE="${LAB}/collection.tar"
tar -cf "${ARCHIVE}" -C "${WORK}" .
if command -v gpg >/dev/null 2>&1; then
  echo "lab-passphrase" | gpg --batch --yes --passphrase-fd 0 -c "${ARCHIVE}" 2>/dev/null
  ARCHIVE="${ARCHIVE}.gpg"; TOOL="gpg"
else
  mv "${ARCHIVE}" "${ARCHIVE}.enc"; ARCHIVE="${ARCHIVE}.enc"; TOOL="tar"
fi
record "{\"kind\":\"archive\",\"ts\":$(now),\"tool\":\"${TOOL}\",\"cmd\":\"archive collection\"}"

echo "[lab] staging archive to removable media (${STAGING})"
cp "${ARCHIVE}" "${STAGING}/"
record "{\"kind\":\"stage\",\"ts\":$(now),\"path\":\"${STAGING}/$(basename "${ARCHIVE}")\"}"

echo "[lab] dropping telemetry-stopped marker and wiping throwaway history"
record "{\"kind\":\"telemetry_stop\",\"ts\":$(now)}"
HIST="${LAB}/.bash_history"
echo "git clone ..." > "${HIST}"; rm -f "${HIST}"
record "{\"kind\":\"history_delete\",\"ts\":$(now),\"path\":\"${HIST}\"}"

echo "[lab] emitting normalized events from the recorded actions"
SCENARIO="${LAB}/scenario"
python3 "${REPO_ROOT}/lab/scenario_actions/emit_events.py" "${ACTIONS}" "${SCENARIO}" "${ACTOR}" "${DEVICE}"

echo "[lab] replaying through the detection pack"
OUTPUT="$(ariadne replay "${SCENARIO}" --rules "${REPO_ROOT}/rules" --no-durability)"
echo "${OUTPUT}"

if echo "${OUTPUT}" | grep -q "Case opened:"; then
  echo "[lab] PASS — expected detection fired on real decoy activity"
else
  echo "[lab] FAIL — detection did not fire" >&2
  exit 1
fi
