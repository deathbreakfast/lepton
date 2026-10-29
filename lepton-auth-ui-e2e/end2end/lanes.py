#!/usr/bin/env python3
"""Helpers for run-lanes.sh. Standard library only; run with `python3 -I`.

A test's key is the line Playwright's --test-list accepts:
`[project] › file › describe › title`, without the `[project] › ` prefix when
the suite has a single unnamed project.

  lanes.py lists     --all ALL.json --lists DIR --n N --out RUN
  lanes.py merge     --all ALL.json --run RUN [--stages RUN/stages.tsv]
  lanes.py parity    --serial SERIAL.json --run RUN
  lanes.py partition --results SERIAL.json --n N --out DIR [--split F ...] [--pin F,F ...]
"""
import argparse
import glob
import json
import os
import sys

SEP = " › "


def walk(suite, path, file):
    """Yield (key, file, test) for every test in a Playwright JSON suite."""
    file = file or suite.get("file") or suite.get("title")
    for spec in suite.get("specs", []):
        for test in spec.get("tests", []):
            title = SEP.join([file, *path, spec["title"]])
            project = test.get("projectName") or ""
            key = f"[{project}]{SEP}{title}" if project else title
            yield key, file, test
    for child in suite.get("suites", []):
        yield from walk(child, path + [child["title"]], file)


def tests_of(report_path):
    with open(report_path) as f:
        report = json.load(f)
    for suite in report.get("suites", []):
        yield from walk(suite, [], None)


def outcome(test):
    """passed, failed, skipped or missing, from the last attempt."""
    results = test.get("results") or []
    if not results:
        return "skipped" if test.get("status") == "skipped" else "missing"
    status = results[-1].get("status")
    if status == "passed":
        return "passed"
    if status == "skipped":
        return "skipped"
    return "failed"


def seconds(test):
    results = test.get("results") or []
    return results[-1].get("duration", 0) / 1000 if results else 0.0


def cmd_lists(a):
    """Write RUN/lane-i/list.txt: committed list i, minus stale lines, plus
    tests no committed list names (dealt round-robin)."""
    expected = [k for k, _, _ in tests_of(a.all)]
    wanted = set(expected)
    lanes, seen, stale = [], set(), 0
    for i in range(1, a.n + 1):
        lines = []
        with open(os.path.join(a.lists, f"list-{i}.txt")) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line in wanted and line not in seen:
                    lines.append(line)
                    seen.add(line)
                else:
                    stale += 1
        lanes.append(lines)
    extra = [k for k in expected if k not in seen]
    for j, key in enumerate(extra):
        lanes[j % a.n].append(key)
    for i, lines in enumerate(lanes, 1):
        d = os.path.join(a.out, f"lane-{i}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "list.txt"), "w") as f:
            f.write("".join(l + "\n" for l in lines))
    print(f"lists: {len(expected)} tests, {len(extra)} not in a committed list "
          f"(dealt round-robin), {stale} stale lines dropped")


def read_stages(path):
    rows = []
    if path and os.path.exists(path):
        with open(path) as f:
            rows = [l.rstrip("\n").split("\t") for l in f if l.strip()]
    return rows


def cmd_merge(a):
    expected = [k for k, _, _ in tests_of(a.all)]
    counts, lanes, failed = {}, [], []
    dead = []
    for d in sorted(glob.glob(os.path.join(a.run, "lane-*")),
                    key=lambda p: int(p.rsplit("-", 1)[1])):
        i = d.rsplit("-", 1)[1]
        row = {"lane": int(i), "tests": 0, "passed": 0, "failed": 0,
               "skipped": 0, "minutes": 0.0, "rc": None}
        timing = os.path.join(d, "timing.tsv")
        if os.path.exists(timing):
            with open(timing) as f:
                cols = f.read().strip().split("\t")
            if len(cols) >= 5:
                row["minutes"] = round((float(cols[3]) - float(cols[1])) / 60, 2)
                row["rc"] = int(cols[4])
        if row["rc"] == 98:
            dead.append(int(i))
        res = os.path.join(d, "results.json")
        if os.path.exists(res):
            for key, _, test in tests_of(res):
                o = outcome(test)
                counts[key] = counts.get(key, 0) + 1
                row["tests"] += 1
                if o in row:
                    row[o] += 1
                if o == "failed":
                    failed.append((int(i), key))
        lanes.append(row)
    missing = [k for k in expected if k not in counts]
    dups = sorted(k for k, n in counts.items() if n > 1)
    unexpected = sorted(k for k in counts if k not in set(expected))
    stages = read_stages(a.stages)
    ok = (not failed and not missing and not dups and not dead
          and all(r["rc"] == 0 for r in lanes))
    summary = {
        "ok": ok, "expected": len(expected), "ran": len(counts),
        "passed": sum(r["passed"] for r in lanes),
        "failed": [{"lane": i, "title": k} for i, k in failed],
        "missing": missing, "duplicates": dups, "unexpected": unexpected,
        "dead_servers": dead, "lanes": lanes,
        "stages": {k: float(v) for k, v in stages},
    }
    with open(os.path.join(a.run, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    md = [f"# Lane run: {'PASS' if ok else 'FAIL'}", "",
          f"{len(expected)} expected, {len(counts)} ran, "
          f"{summary['passed']} passed, {len(failed)} failed, "
          f"{len(missing)} missing, {len(dups)} duplicated.", ""]
    if stages:
        md += ["| Stage | Minutes |", "|---|---|"]
        md += [f"| {k} | {float(v) / 60:.1f} |" for k, v in stages]
        md.append("")
    md += ["| Lane | Tests | Passed | Failed | Skipped | Minutes | rc |",
           "|---|---|---|---|---|---|---|"]
    md += [f"| {r['lane']} | {r['tests']} | {r['passed']} | {r['failed']} | "
           f"{r['skipped']} | {r['minutes']} | {r['rc']} |" for r in lanes]
    for label, items in (("Failed", [f"lane {i}: {k}" for i, k in failed]),
                         ("Missing (never ran)", missing),
                         ("Duplicated", dups),
                         ("Server never ready, lane", [str(i) for i in dead])):
        if items:
            md += ["", f"## {label}", ""] + [f"- {x}" for x in items]
    with open(os.path.join(a.run, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    return 0 if ok else 1


def cmd_parity(a):
    serial = {k: outcome(t) for k, _, t in tests_of(a.serial)}
    laned = {}
    for res in glob.glob(os.path.join(a.run, "lane-*", "results.json")):
        for k, _, t in tests_of(res):
            laned.setdefault(k, []).append(outcome(t))
    only_serial = sorted(set(serial) - set(laned))
    only_laned = sorted(set(laned) - set(serial))
    dups = sorted(k for k, v in laned.items() if len(v) > 1)
    order_dep = sorted(k for k, v in laned.items()
                       if serial.get(k) == "passed" and "failed" in v)
    fixed = sorted(k for k, v in laned.items()
                   if serial.get(k) == "failed" and v == ["passed"])
    both = sorted(k for k, v in laned.items()
                  if serial.get(k) == "failed" and "failed" in v)
    ok = not (only_serial or only_laned or dups or order_dep)
    out = [f"# Parity: {'OK' if ok else 'DIFFERS'}", "",
           f"serial {len(serial)} titles, laned {len(laned)}; "
           f"{len(only_serial)} only serial, {len(only_laned)} only laned, "
           f"{len(dups)} duplicated; {len(order_dep)} pass serially but fail "
           f"laned; {len(both)} fail in both; {len(fixed)} fail serially only."]
    for label, items in (("Only in the serial run", only_serial),
                         ("Only in the laned run", only_laned),
                         ("Duplicated in the laned run", dups),
                         ("Pass serially, fail laned (order-dependent)", order_dep),
                         ("Fail in both", both),
                         ("Fail serially, pass laned", fixed)):
        if items:
            out += ["", f"## {label}", ""] + [f"- {x}" for x in items]
    text = "\n".join(out) + "\n"
    with open(os.path.join(a.run, "parity.md"), "w") as f:
        f.write(text)
    print(text)
    return 0 if ok else 1


def cmd_partition(a):
    """Longest unit first onto the least-loaded list. A unit is one
    (project, file), one test of a --split file, or one (project, --pin
    group). Each list keeps the suite's own order."""
    split = set(a.split or [])
    pins = {}
    for group in a.pin or []:
        for f in group.split(","):
            pins[f] = group
    units, order = {}, {}
    for n, (key, file, test) in enumerate(tests_of(a.results)):
        project = test.get("projectName") or ""
        if file in split:
            unit = ("test", key)
        else:
            unit = (project, pins.get(file, file))
        units.setdefault(unit, []).append((key, seconds(test)))
        order[key] = n
    loads = [[0.0, []] for _ in range(a.n)]
    for unit in sorted(units, key=lambda u: -sum(s for _, s in units[u])):
        lane = min(loads, key=lambda l: l[0])
        lane[0] += sum(s for _, s in units[unit])
        lane[1].extend(k for k, _ in units[unit])
    os.makedirs(a.out, exist_ok=True)
    plan = {"n": a.n, "total_seconds": round(sum(l[0] for l in loads), 1),
            "lists": []}
    for i, (load, keys) in enumerate(loads, 1):
        keys.sort(key=order.get)
        with open(os.path.join(a.out, f"list-{i}.txt"), "w") as f:
            f.write("".join(k + "\n" for k in keys))
        plan["lists"].append({"index": i, "tests": len(keys),
                              "predicted_seconds": round(load, 1)})
    with open(os.path.join(a.out, "plan.json"), "w") as f:
        json.dump(plan, f, indent=2)
    print(json.dumps(plan, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("lists")
    s.add_argument("--all", required=True)
    s.add_argument("--lists", required=True)
    s.add_argument("--n", type=int, required=True)
    s.add_argument("--out", required=True)
    s = sub.add_parser("merge")
    s.add_argument("--all", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--stages")
    s = sub.add_parser("parity")
    s.add_argument("--serial", required=True)
    s.add_argument("--run", required=True)
    s = sub.add_parser("partition")
    s.add_argument("--results", required=True)
    s.add_argument("--n", type=int, required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--split", nargs="*")
    s.add_argument("--pin", nargs="*")
    a = p.parse_args()
    return {"lists": cmd_lists, "merge": cmd_merge, "parity": cmd_parity,
            "partition": cmd_partition}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
