#!/usr/bin/env bash
# Runs the whole experiment: N users, REPS repetitions of each configuration.
#   ./run_all.sh            (N=100, REPS=3, concurrency 10)
#   N=40 REPS=1 ./run_all.sh
set -euo pipefail
cd "$(dirname "$0")"
N=${N:-100}; REPS=${REPS:-3}; CONC=${CONC:-10}
HL="hl1 hl2 hl3 hl4 hl5"
RUN="docker compose run --rm -T client python run_experiment.py"

mkdir -p results; rm -f results/*.json results/summary.md
docker build -t kcabe:v1 . > /dev/null
docker compose down > /dev/null 2>&1 || true
docker run --rm -v "$PWD":/app kcabe:v1 python setup_once.py --n "$N"

for rep in $(seq 1 "$REPS"); do
  echo "===== repetition $rep/$REPS ====="

  echo "--- baseline"
  docker compose down > /dev/null 2>&1
  docker compose up -d pkg
  $RUN --mode baseline --n "$N" --conc "$CONC" --rep "$rep"

  echo "--- case A: PKG enrolls only the trusted users"
  docker compose down > /dev/null 2>&1
  docker compose up -d pkg $HL
  $RUN --mode partial --n "$N" --conc "$CONC" --rep "$rep"

  echo "--- case B: PKG stopped before the user phase"
  docker compose down > /dev/null 2>&1
  docker compose up -d pkg $HL
  $RUN --snapshot-pkg
  docker compose stop pkg
  $RUN --mode offline --n "$N" --conc "$CONC" --rep "$rep"
done

docker compose down > /dev/null 2>&1
docker run --rm -v "$PWD":/app kcabe:v1 python summarize.py results
