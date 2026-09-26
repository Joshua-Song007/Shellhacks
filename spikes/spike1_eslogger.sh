#!/bin/bash
# SPIKE-1: does `eslogger` stream exec/fork/exit/open/create/rename/unlink on
# this Mac with the privileges we have? PASS -> Scout uses FR-D-2 (eslogger).
# FAIL -> Scout uses the FR-D-3 degraded path (libproc + kqueue + FSEvents).
#
# eslogger streams system-wide into a FIFO drained by a reader that stamps
# each line's arrival time, exactly as Scout will consume it. The reader only
# counts other processes' events; it persists ONLY lines that mention the
# spike's scratch dir into spikes/out/ as a fixture for source_eslogger.rs.
# (`--select` matched nothing on macOS 26.4 in an earlier run, so filtering
# happens here.)
#
# The benign trigger runs under three launch conditions, one subdir each:
#   a/  run as root by this script
#   c/  run by this script as the invoking user (sudo -u)
#   b/  run by hand from a second terminal (independent of this script)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 2
fi

ITERATIONS="${1:-2000}"
MANUAL_WAIT_S="${2:-120}"
SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK=/private/tmp/tcell-spike1
FIFO=/private/tmp/tcell-spike1.fifo
OUT_DIR="$SPIKE_DIR/out"
OUT="$OUT_DIR/eslogger_sample.ndjson"
ARRIVALS="$OUT_DIR/arrivals.ns"
SEEN="$OUT_DIR/total_seen.count"
ERR="$OUT_DIR/eslogger.stderr"
ES_PID=""
READER_PID=""

# Background jobs in a non-interactive shell start with SIGINT ignored, so
# eslogger is stopped with SIGTERM, escalating to SIGKILL after 5s.
stop_eslogger() {
  [[ -n "$ES_PID" ]] || return 0
  kill -TERM "$ES_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$ES_PID" 2>/dev/null || break
    sleep 0.5
  done
  kill -KILL "$ES_PID" 2>/dev/null || true
  wait "$ES_PID" 2>/dev/null || true
  ES_PID=""
  if [[ -n "$READER_PID" ]]; then
    wait "$READER_PID" 2>/dev/null || true
    READER_PID=""
  fi
}

cleanup() {
  stop_eslogger
  [[ -z "$READER_PID" ]] || kill "$READER_PID" 2>/dev/null || true
  rm -rf "$WORK" "$FIFO"
  if [[ -n "${SUDO_USER:-}" ]]; then chown -R "$SUDO_USER" "$OUT_DIR"; fi
}
trap cleanup EXIT

rm -rf "$WORK" "$FIFO" "$OUT" "$ARRIVALS" "$SEEN" "$ERR"
mkdir -p "$WORK/a" "$WORK/b" "$WORK/c" "$OUT_DIR"
chmod 755 "$WORK" "$WORK/a"
chmod 777 "$WORK/b" "$WORK/c"
cc -O0 -o "$WORK/a/trigger" "$SPIKE_DIR/spike1_trigger.c"
cp "$WORK/a/trigger" "$WORK/b/trigger"
cp "$WORK/a/trigger" "$WORK/c/trigger"
chmod 755 "$WORK"/*/trigger
mkfifo "$FIFO"

perl -MTime::HiRes=time -MIO::Handle -e '
  my ($out, $arr, $fifo, $seen, $mark) = @ARGV;
  open(my $raw, ">", $out) or die "open $out: $!";
  open(my $ts,  ">", $arr) or die "open $arr: $!";
  $raw->autoflush(1); $ts->autoflush(1);
  open(my $in, "<", $fifo) or die "open $fifo: $!";
  my ($n, $min, $max, $gaps, $prev, %kinds) = (0, undef, undef, 0, undef);
  while (my $l = <$in>) {
    my $t = time();
    $n++;
    if ($l =~ /"global_seq_num":(\d+)/) {
      my $g = $1;
      $min = $g if !defined $min || $g < $min;
      $max = $g if !defined $max || $g > $max;
      $gaps += $g - $prev - 1 if defined $prev && $g > $prev + 1;
      $prev = $g if !defined $prev || $g > $prev;
    }
    $kinds{$1}++ if $l =~ /"event":\{"(\w+)"/;
    next if index($l, $mark) < 0;
    printf $ts "%d\n", $t * 1e9;
    print $raw $l;
  }
  open(my $s, ">", $seen) or die "open $seen: $!";
  print $s "delivered=$n global_seq_min=" . ($min // "?") . " global_seq_max=" . ($max // "?") . " seq_gap_events=$gaps\n";
  print $s join(" ", map { "$_=$kinds{$_}" } sort keys %kinds), "\n";
' "$OUT" "$ARRIVALS" "$FIFO" "$SEEN" "tcell-spike1" &
READER_PID=$!

eslogger exec fork exit open create rename unlink >"$FIFO" 2>"$ERR" &
ES_PID=$!
sleep 2

if ! kill -0 "$ES_PID" 2>/dev/null; then
  echo "FAIL: eslogger exited during startup:" >&2
  cat "$ERR" >&2
  echo "hint: grant Full Disk Access to this terminal app (System Settings > Privacy & Security), then retry" >&2
  exit 1
fi

run_trigger() {
  local label="$1"; shift
  local rc=0
  "$@" || rc=$?
  echo "trigger $label: $ITERATIONS iterations, exit code $rc"
}

run_trigger "a (root, script child)" \
  bash -c "cd '$WORK/a' && exec env -i PATH=/usr/bin:/bin '$WORK/a/trigger' '$ITERATIONS'"

if [[ -n "${SUDO_USER:-}" ]]; then
  run_trigger "c ($SUDO_USER via sudo -u, script child)" \
    sudo -u "$SUDO_USER" bash -c "cd '$WORK/c' && exec env -i PATH=/usr/bin:/bin '$WORK/c/trigger' '$ITERATIONS'"
else
  echo "trigger c: skipped (SUDO_USER unset)"
fi

echo
echo ">>> Now, in a SECOND terminal tab (as your normal user, no sudo), run:"
echo "    cd $WORK/b && ./trigger $ITERATIONS && touch done"
echo ">>> Waiting up to ${MANUAL_WAIT_S}s for it..."
for ((i = 0; i < MANUAL_WAIT_S * 2; i++)); do
  [[ -e "$WORK/b/done" ]] && break
  sleep 0.5
done
if [[ -e "$WORK/b/done" ]]; then echo "trigger b (manual, independent): done"; else echo "trigger b: not run (timed out)"; fi

sleep 2
stop_eslogger
TOTAL=$(wc -l <"$OUT" | tr -d ' ')

echo
echo "system-wide stream (counts only):"
sed 's/^/  /' "$SEEN" 2>/dev/null || echo "  (reader wrote no stats)"
if [[ -s "$ERR" ]]; then echo "eslogger stderr:"; cat "$ERR"; fi
echo "kept $TOTAL lines mentioning the scratch dir -> $OUT"

echo "events emitted BY each trigger (process = trigger), by condition and kind:"
jq -r '
  .process.executable.path as $p
  | select($p | test("tcell-spike1/[abc]/trigger$"))
  | "  \($p | capture("tcell-spike1/(?<c>[abc])/").c)  \(.event | keys[0])"
' "$OUT" | sort | uniq -c || true
echo "events from OTHER processes touching the scratch dir (e.g. Gatekeeper/XProtect scans):"
jq -r '.process.executable.path | select(test("tcell-spike1/[abc]/trigger$") | not)' "$OUT" | sort | uniq -c | sed 's/^/  /' || true

echo "pipeline lag, arrival minus eslogger event time (NFR-1):"
perl -MTime::Local -e '
  open(my $afh, "<", $ARGV[0]) or die; open(my $ofh, "<", $ARGV[1]) or die;
  my @lag;
  while (defined(my $t = <$afh>) and defined(my $l = <$ofh>)) {
    next unless $l =~ /"time":"(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.(\d+)Z"/;
    my $ev = timegm($6, $5, $4, $3, $2 - 1, $1) * 1e9 + substr($7 . "000000000", 0, 9);
    push @lag, ($t - $ev) / 1e6;
  }
  exit(print "  (no timestamped lines)\n") unless @lag;
  @lag = sort { $a <=> $b } @lag;
  printf "  n=%d  median=%.2f ms  p95=%.2f ms  max=%.2f ms\n",
    scalar @lag, $lag[int($#lag / 2)], $lag[int($#lag * 0.95)], $lag[-1];
' "$ARRIVALS" "$OUT"

echo "field checks:"
jq -s '{
  has_pidversion: all(.[]; .process.audit_token.pidversion != null),
  has_global_seq: all(.[]; .global_seq_num != null),
  has_mach_time:  all(.[]; .mach_time != null)
}' "$OUT"

verdict_for() {
  jq -r --arg c "$1" '
    select(.process.executable.path | test("tcell-spike1/" + $c + "/trigger$")) | .event | keys[0]
  ' "$OUT" | sort -u | tr '\n' ' '
}
for c in a c b; do
  kinds=" $(verdict_for "$c")"
  missing=""
  for want in exec fork exit open create rename unlink; do
    [[ "$kinds" == *" $want "* ]] || missing+=" $want"
  done
  echo "condition $c: observed[${kinds% }] missing[${missing# }]"
done
