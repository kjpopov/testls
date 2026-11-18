#!/usr/bin/env python3
"""Run a local, clean-room fixture comparison; never publish issues or alter services."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
# Public output field identifiers, not external implementation or cipher tables.
EXTERNAL_PROTOCOLS = dict(zip(
    ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"), PROTOCOLS, strict=True))
CIPHER_PROTOCOLS = dict(zip(
    ("ssl2", "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"), PROTOCOLS, strict=True))
EXTERNAL_VULNS = {"heartbleed": "heartbleed", "CCS": "ccs_injection",
                  "ROBOT": "robot", "ticketbleed": "ticketbleed"}
STATUSES = {"vulnerable", "not vulnerable", "not tested"}
MAX_JSON = 16 * 1024 * 1024


def unique_object(pairs):
    """Reject duplicate object keys rather than silently losing evidence."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_bytes(path):
    """Read one bounded JSON snapshot for parsing and provenance hashing."""
    with Path(path).open("rb") as source:
        body = source.read(MAX_JSON + 1)
    if len(body) > MAX_JSON:
        raise ValueError("JSON exceeds 16 MiB")
    return body


def parse_json(body):
    """Parse a JSON snapshot with duplicate-key and non-finite-number rejection."""
    return json.loads(body, object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def load_json(path):
    """Load bounded JSON using the same strict decoder as manifest snapshots."""
    return parse_json(json_bytes(path))


def reject_constant(value):
    """Reject nonstandard JSON numeric constants."""
    raise ValueError(f"nonstandard JSON number: {value}")


def manifest(path, selected, *, body=None):
    """Validate a loopback-only fixture manifest and select unique known names."""
    data = load_json(path) if body is None else parse_json(body)
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("unsupported audit manifest schema")
    pin = data.get("comparator", {})
    if (not isinstance(pin, dict)
            or not re.fullmatch(r"[0-9a-f]{40}", str(pin.get("revision", "")))
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(pin.get("tag", "")))):
        raise ValueError("comparator needs an exact revision and release tag")
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("manifest needs fixtures")
    names, ports = set(), set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise ValueError("fixture must be an object")
        if not {"name", "port", "starttls", "protocols"} <= set(fixture):
            raise ValueError("fixture lacks required fields")
        if set(fixture) - {"name", "port", "starttls", "protocols", "vulnerabilities"}:
            raise ValueError("unknown fixture field (hosts and arbitrary flags are forbidden)")
        name, port = fixture.get("name"), fixture.get("port")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            raise ValueError("invalid fixture name")
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("fixture port must be 1024..65535")
        if name in names or port in ports:
            raise ValueError("duplicate fixture name or port")
        names.add(name)
        ports.add(port)
        if fixture.get("starttls") not in (None, "smtp", "imap", "pop3", "ftp", "xmpp",
                                          "ldap", "postgres", "mysql"):
            raise ValueError("unsupported STARTTLS mode")
        versions = fixture.get("protocols")
        if (not isinstance(versions, list) or not versions
                or any(not isinstance(version, str) or version not in PROTOCOLS for version in versions)
                or len(set(versions)) != len(versions)):
            raise ValueError("invalid expected protocols")
        checks = fixture.get("vulnerabilities", {})
        if (not isinstance(checks, dict) or set(checks) - set(EXTERNAL_VULNS.values())
                or any(value not in ("vulnerable", "no_positive") for value in checks.values())):
            raise ValueError("invalid vulnerability expectation")
    if len(set(selected)) != len(selected) or set(selected) - names:
        raise ValueError("fixture selection must contain unique known names")
    data["fixtures"] = [f for f in fixtures if not selected or f["name"] in selected]
    return data


def testls_result(data):
    """Normalize schema-v1/v2 testls measurements, retaining unknown and failed sections."""
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] not in (1, 2)):
        raise ValueError("unsupported testls JSON schema")
    result = {"protocols": {}, "ciphers": {}, "vulnerabilities": {}, "incomplete": []}
    for row in data["protocols"]:
        version, status = row["version"], row["status"]
        if version not in PROTOCOLS or status not in {"offered", "not_offered", "error"}:
            raise ValueError("invalid testls protocol result")
        if version in result["protocols"]:
            raise ValueError("duplicate testls protocol")
        result["protocols"][version] = status
    for row in data["ciphers"]:
        version = row["protocol"]
        if version not in PROTOCOLS or version in result["ciphers"]:
            raise ValueError("invalid or duplicate cipher section")
        suites = []
        for suite in row["suites"]:
            width = 6 if version == "SSLv2" else 4
            if not re.fullmatch(rf"0x[0-9a-fA-F]{{{width}}}", suite["id"]):
                raise ValueError("invalid IANA suite identifier")
            suites.append(int(suite["id"], 16))
        if len(set(suites)) != len(suites):
            raise ValueError("duplicate suite")
        result["ciphers"][version] = sorted(suites)
        if row.get("error"):
            result["incomplete"].append(f"cipher enumeration failed: {version}")
    for row in data["vulnerabilities"]:
        if row["id"] in result["vulnerabilities"] or row["status"] not in STATUSES:
            raise ValueError("invalid or duplicate vulnerability")
        result["vulnerabilities"][row["id"]] = row["status"]
    return complete_sections(result)


def external_result(data):
    """Adapt documented flat comparator output without importing wording or tables."""
    if not isinstance(data, list):
        raise ValueError("comparator output must be a flat JSON array")
    result = {"protocols": {}, "ciphers": {}, "vulnerabilities": {}, "incomplete": []}
    relevant = set()
    for row in data:
        identifier = row["id"]
        cipher = re.fullmatch(r"cipher-(ssl2|ssl3|tls1(?:_[123])?)_x([0-9a-fA-F]+)", identifier)
        if identifier.startswith("cipher-") and not cipher:
            raise ValueError("unsupported comparator cipher identifier")
        if identifier not in EXTERNAL_PROTOCOLS and identifier not in EXTERNAL_VULNS and not cipher:
            continue
        if identifier in relevant:
            raise ValueError("duplicate comparator measurement")
        relevant.add(identifier)
        finding = row.get("finding", "").lower().strip()
        if identifier in EXTERNAL_PROTOCOLS:
            version = EXTERNAL_PROTOCOLS[identifier]
            if re.match(r"not offered\b", finding):
                status = "not_offered"
            elif re.match(r"offered\b", finding):
                status = "offered"
            else:
                status = "error"
            result["protocols"][version] = status
        elif cipher:
            # RFC 5246 section 7.4.1.2 defines two-octet TLS suite identifiers.
            # SSLv2 identifiers have three octets; no name-based lookup is used.
            version = CIPHER_PROTOCOLS[cipher[1]]
            if len(cipher[2]) != (6 if version == "SSLv2" else 4):
                raise ValueError("wrong cipher identifier width")
            number = int(cipher[2], 16)
            suites = result["ciphers"].setdefault(version, [])
            if number in suites:
                raise ValueError("duplicate comparator suite")
            suites.append(number)
        else:
            status = "not tested"
            if re.match(r"not vulnerable\b", finding):
                status = "not vulnerable"
            elif re.match(r"vulnerable\b", finding):
                status = "vulnerable"
            result["vulnerabilities"][EXTERNAL_VULNS[identifier]] = status
    for suites in result["ciphers"].values():
        suites.sort()
    # Verified v3.2.5 completion output contains INFO and elapsed whole seconds.
    completion = [row for row in data if row.get("id") == "scanTime"]
    if len(completion) != 1:
        result["incomplete"].append("comparator completion record missing or duplicated")
    elif (completion[0].get("severity") != "INFO"
          or not isinstance(completion[0].get("finding"), str)
          or not re.fullmatch(r"[0-9]+", completion[0]["finding"])):
        result["incomplete"].append("comparator completion record is not successful")
    return complete_sections(result)


def complete_sections(result):
    """Mark absent, failed or internally inconsistent protocol/cipher sections incomplete."""
    for version in PROTOCOLS:
        status = result["protocols"].get(version)
        if status not in {"offered", "not_offered"}:
            result["incomplete"].append(f"protocol unmeasured: {version}")
        if status == "offered" and not result["ciphers"].get(version):
            result["incomplete"].append(f"cipher enumeration missing: {version}")
        if status != "offered" and result["ciphers"].get(version):
            result["incomplete"].append(f"cipher/protocol contradiction: {version}")
    return result


def compare(fixture, left, right):
    """Compare measurements and fixture controls without declaring either tool ground truth."""
    differences, notes = [], []
    incomplete = left["incomplete"] + right["incomplete"]
    for version in PROTOCOLS:
        a, b = left["protocols"].get(version), right["protocols"].get(version)
        if a in {"offered", "not_offered"} and b in {"offered", "not_offered"} and a != b:
            differences.append(f"protocol disagreement: {version}")
        if a == b == "offered":
            ours, theirs = set(left["ciphers"].get(version, [])), set(right["ciphers"].get(version, []))
            if ours and theirs and ours != theirs:
                differences.append(f"suite disagreement: {version}; testls-only "
                                   f"{suite_ids(ours - theirs)}; comparator-only {suite_ids(theirs - ours)}")
        expected = "offered" if version in fixture["protocols"] else "not_offered"
        for tool, status in (("testls", a), ("comparator", b)):
            if status in {"offered", "not_offered"} and status != expected:
                differences.append(f"fixture protocol expectation: {tool} {version}")
    for check, expected in fixture.get("vulnerabilities", {}).items():
        for tool, result in (("testls", left), ("comparator", right)):
            status = result["vulnerabilities"].get(check)
            if status is None:
                incomplete.append(f"fixture control missing: {tool} {check}")
            elif expected == "vulnerable" and status == "not tested":
                incomplete.append(f"positive fixture control inconclusive: {tool} {check}")
            elif ((expected == "vulnerable" and status != "vulnerable")
                  or (expected == "no_positive" and status == "vulnerable")):
                differences.append(f"fixture vulnerability expectation: {tool} {check}")
    for check in EXTERNAL_VULNS.values():
        a, b = left["vulnerabilities"].get(check), right["vulnerabilities"].get(check)
        if a is None or b is None or "not tested" in (a, b):
            notes.append(f"{check}: inconclusive or missing; not a negative result")
        elif a != b:
            differences.append(f"vulnerability disagreement: {check} ({a} / {b})")
    return {"name": fixture["name"], "status": "incomplete" if incomplete else
            "review" if differences else "agree", "differences": differences,
            "incomplete": sorted(set(incomplete)), "notes": notes}


def suite_ids(values):
    """Render sorted numeric IANA identifiers without relying on cipher names."""
    return ", ".join(f"0x{value:04x}" for value in sorted(values)) or "none"


def digest(path):
    """Hash a file incrementally for reproducibility metadata."""
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def executable(path):
    """Resolve an existing executable, never downloading or installing one."""
    found = shutil.which(str(path))
    if not found:
        raise ValueError(f"executable unavailable: {path}")
    return Path(found).resolve()


def commands(fixture, args, checkout):
    """Build argument arrays restricted to the named local fixture and explicit tool paths."""
    target = f"127.0.0.1:{fixture['port']}"
    ours = [str(args.testls), "--profile", "default", "--intrusive", "--connect-timeout", "3",
            "--read-timeout", "3", "--sni", "localhost", "--ca-file", str(args.ca),
            "--color", "never", "--format", "json"]
    theirs = [str(args.bash), str(checkout / "testssl.sh"), "--openssl", str(args.openssl),
              "--warnings", "batch", "--color", "0", "--nodns", "none", "--ip", "127.0.0.1",
              "--add-ca", str(args.ca), "--connect-timeout", "3", "--openssl-timeout", "5",
              "--disable-rating", "-p", "-s", "-E", "-P", "-f", "-S", "-h", "-U", "-g"]
    if fixture["starttls"]:
        ours += ["--starttls", fixture["starttls"]]
        theirs += ["--starttls", fixture["starttls"]]
    if fixture["starttls"] == "xmpp":
        theirs += ["--xmpphost", "localhost"]
    return ours + [target], theirs


def terminate(process):
    """Stop only the owned Unix process group, including scanner subprocesses."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def child_environment():
    """Allow only tool discovery and fixed locale settings, disabling external revocation queries."""
    return {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C", "LANG": "C",
            "TZ": "UTC", "PHONE_OUT": "false"}


def capture(command, cwd, stdout, stderr, budget):
    """Capture separate private outputs and bound runtime, including interruption cleanup."""
    started = time.monotonic()
    environment = child_environment()
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err,
                                   start_new_session=True, env=environment)
        timed_out = False
        try:
            process.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            terminate(process)
    return {"command": command, "cwd": str(cwd), "exit_code": process.returncode,
            "timed_out": timed_out, "seconds": round(time.monotonic() - started, 3),
            "environment": environment}


def inspect_tool(command, cwd):
    """Capture small version/control output with a fixed deadline."""
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True,
                            timeout=10, text=True, env=child_environment())
    if len(result.stdout) > 8192:
        raise ValueError("unexpectedly large tool metadata")
    return result.stdout.strip()


def checkout_identity(data, checkout):
    """Validate the comparator root, release and clean state on every provenance check."""
    top = Path(inspect_tool(["git", "rev-parse", "--show-toplevel"], checkout)).resolve()
    if top != checkout:
        raise ValueError("comparator path must be its checkout root")
    revision = inspect_tool(["git", "rev-parse", "HEAD"], checkout)
    if revision != data["comparator"]["revision"]:
        raise ValueError("comparator checkout does not match the manifest pin")
    release = inspect_tool(["git", "rev-parse", f"{data['comparator']['tag']}^{{commit}}"], checkout)
    if release != revision:
        raise ValueError("comparator release tag does not match the pinned revision")
    if inspect_tool(["git", "status", "--porcelain", "--untracked-files=all"], checkout):
        raise ValueError("comparator checkout must be clean (write outputs elsewhere)")
    return {"revision": revision, "tag": data["comparator"]["tag"]}


def file_identity(path):
    """Record bytes and inode identity, rejecting a file that changes while being hashed."""
    path = Path(path).resolve()
    before = path.stat()
    checksum = digest(path)
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("audit input changed while hashing")
    return {"path": str(path), "sha256": checksum, "device": after.st_dev,
            "inode": after.st_ino, "size": after.st_size, "mtime_ns": after.st_mtime_ns,
            "ctime_ns": after.st_ctime_ns}


def provenance(args, data, checkout):
    """Snapshot the pinned checkout and all scanner/configuration files without inspecting source."""
    return {"comparator": checkout_identity(data, checkout), "environment": child_environment(),
            "files": {name: file_identity(path) for name, path in (
                ("testls", args.testls), ("openssl", args.openssl), ("bash", args.bash),
                ("timeout", args.timeout), ("ca", args.ca), ("manifest", args.manifest),
                ("comparator_script", checkout / "testssl.sh"))}}


def metadata(args, data, checkout):
    """Require clean pinned inputs and record exact binary/configuration provenance."""
    inputs = provenance(args, data, checkout)
    checksums = inputs["files"]
    if checksums["manifest"]["sha256"] != args.manifest_sha256:
        raise ValueError("manifest changed after its configuration was read")
    return {"schema_version": 1, "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "platform": platform.platform(), "repository_revision": inspect_tool(
                ["git", "rev-parse", "HEAD"], ROOT),
            "repository_dirty": bool(inspect_tool(["git", "status", "--porcelain"], ROOT)),
            "inputs": inputs, "manifest_sha256": args.manifest_sha256,
            "ca_sha256": checksums["ca"]["sha256"],
            "comparator": {**data["comparator"], "script_sha256": checksums["comparator_script"]["sha256"]},
            "timeout": checksums["timeout"],
            "testls": {"path": str(args.testls), "sha256": checksums["testls"]["sha256"],
                        "version": inspect_tool([str(args.testls), "--version"], ROOT)},
            "openssl": {"path": str(args.openssl), "sha256": checksums["openssl"]["sha256"],
                         "version": inspect_tool([str(args.openssl), "version"], ROOT)},
            "bash": {"path": str(args.bash), "sha256": checksums["bash"]["sha256"],
                      "version": inspect_tool([str(args.bash), "--version"], ROOT)}}


def checked_provenance(args, data, checkout):
    """Retain a failed provenance check as local evidence instead of losing earlier measurements."""
    try:
        return provenance(args, data, checkout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"error": "input or comparator checkout unavailable, changed or unpinned"}


def verified_capture(command, cwd, stdout, stderr, budget, args, data, checkout, recorded):
    """Check inputs around each invocation; skip changed inputs and never misattribute output."""
    before = checked_provenance(args, data, checkout)
    matches = before == recorded
    if matches:
        run = capture(command, cwd, stdout, stderr, budget)
    else:
        run = {"command": command, "cwd": str(cwd), "exit_code": None,
               "timed_out": False, "seconds": 0, "skipped": True}
    after = checked_provenance(args, data, checkout)
    return {**run, "provenance_before": before, "provenance_after": after,
            "attributed_to_recorded_inputs": matches and after == recorded}


def measurement(path, parser, run, valid_codes):
    """Separate parseable measurements from failed execution, retaining partial evidence."""
    try:
        result = parser(load_json(path))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        result = {"protocols": {}, "ciphers": {}, "vulnerabilities": {},
                  "incomplete": ["output absent, malformed or unsupported"]}
    if not run.get("attributed_to_recorded_inputs", True):
        result["incomplete"].append("scanner inputs changed; output not attributed to recorded provenance")
    if run.get("skipped"):
        result["incomplete"].append("scanner skipped after provenance mismatch")
    elif run["timed_out"] or run["exit_code"] < 0:
        result["incomplete"].append("scanner timed out or was terminated")
    elif valid_codes is not None and run["exit_code"] not in valid_codes:
        result["incomplete"].append("scanner failed")
    elif valid_codes is None and run["exit_code"] != 0:
        # The public manual defines nonzero codes as errors/ambiguities, not completeness evidence.
        result["incomplete"].append("comparator returned a nonzero exit status; enumeration unconfirmed")
    # A completion record cannot establish complete enumeration after any nonzero exit.
    return result


def write_json(path, value):
    """Write stable, machine-readable local evidence without raw scanner descriptions."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def reports(output, evidence):
    """Render a standardized summary and unconfirmed, review-only issue drafts."""
    write_json(output / "summary.json", evidence)
    state = "completed" if evidence.get("complete_run") else "unfinished"
    lines = ["# Local fixture audit", "", f"Run state: {state}.", "",
             "Agreement covers measured protocols and suite sets only.",
             "Incomplete and not-tested results are not evidence of safety.", "",
             "| Fixture | Result | Differences | Incomplete sections |",
             "| --- | --- | --- | --- |"]
    for row in evidence["results"]:
        lines.append(f"| {row['name']} | {row['status']} | {len(row['differences'])} | "
                     f"{len(row['incomplete'])} |")
        if row["differences"] or row["incomplete"]:
            draft = [f"# Unconfirmed local audit: {row['name']}", "",
                     "Do not publish until independently reproduced and checked against existing issues.",
                     "Neither scanner is ground truth. Not-tested is not a negative result.", "",
                     "## Candidate differences", *[f"- {item}" for item in row["differences"]],
                     "", "## Environment / incomplete measurements",
                     *[f"- {item}" for item in row["incomplete"]], "", "## Reproduction"]
            for run in row["runs"].values():
                draft += ["", "```sh", shlex.join(run["command"]), "```"]
            draft += ["", "## Confirmation checklist", "- Repeat sequentially with healthy fixtures.",
                      "- Reproduce using an independent handshake and primary RFC/IANA references.",
                      "- Separate fixture/tool failures, policy differences and probe scope.",
                      "- Search existing issues; redact raw logs and ephemeral secrets.",
                      "- Only then publish and link a confirmed roadmap item."]
            (output / f"{row['name']}.issue-draft.md").write_text("\n".join(draft) + "\n", encoding="utf-8")
    for row in evidence["results"]:
        lines += ["", f"## {row['name']}",
                  *[f"- Review: {item}" for item in row["differences"]],
                  *[f"- Incomplete: {item}" for item in row["incomplete"]],
                  *[f"- Scope: {item}" for item in row.get("notes", [])]]
    lines += ["", "Raw logs are private local diagnostics; review and redact before sharing.",
              "No GitHub issues or roadmap changes are made by this command."]
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_audit(args, data):
    """Scan selected existing fixtures sequentially and checkpoint reports after each pair."""
    if os.name != "posix":
        raise ValueError("runner requires Unix process-group support (macOS or Linux)")
    checkout = args.testssl_dir.resolve()
    if checkout == ROOT or ROOT in checkout.parents:
        raise ValueError("comparator checkout must be outside this repository")
    args.testls, args.openssl, args.bash = map(executable, (args.testls, args.openssl, args.bash))
    args.timeout = executable("timeout")
    args.ca = args.ca.resolve()
    evidence = {"metadata": {**metadata(args, data, checkout), "fixture_count": len(data["fixtures"]),
                             "budgets": {"testls": args.testls_budget,
                                         "comparator": args.comparator_budget}}, "results": []}
    output = args.output.resolve()
    if output == checkout or checkout in output.parents:
        raise ValueError("outputs must be outside the external comparator checkout")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for fixture in data["fixtures"]:
            name = fixture["name"]
            ours, theirs = commands(fixture, args, checkout)
            theirs += ["--jsonfile", str(output / f"{name}.testssl.json"), f"localhost:{fixture['port']}"]
            recorded = evidence["metadata"]["inputs"]
            runs = {"testls": verified_capture(ours, ROOT, output / f"{name}.testls.json",
                                              output / f"{name}.testls.stderr", args.testls_budget,
                                              args, data, checkout, recorded)}
            runs["comparator"] = verified_capture(theirs, checkout, output / f"{name}.testssl.log",
                                                  output / f"{name}.testssl.stderr", args.comparator_budget,
                                                  args, data, checkout, recorded)
            left = measurement(output / f"{name}.testls.json", testls_result, runs["testls"], {0, 1})
            right = measurement(output / f"{name}.testssl.json", external_result, runs["comparator"], None)
            row = {**compare(fixture, left, right), "fixture": fixture,
                   "measurements": {"testls": left, "comparator": right}, "runs": runs}
            evidence["results"].append(row)
            reports(output, evidence)
            print(f"{name}: {row['status']}", flush=True)
    finally:
        evidence["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["complete_run"] = len(evidence["results"]) == len(data["fixtures"])
        reports(output, evidence)
    return 2 if any(row["incomplete"] for row in evidence["results"]) else \
        1 if any(row["differences"] for row in evidence["results"]) else 0


def positive_seconds(value):
    """Validate finite process budgets within a fixed one-hour maximum."""
    number = int(value)
    if not 1 <= number <= 3600:
        raise argparse.ArgumentTypeError("budget must be 1..3600 seconds")
    return number


def main():
    """Expose side-effect-free planning and explicit local execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--manifest", type=Path, default=ROOT / "tests/servers/audit.json")
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--testls", type=Path, default=ROOT / "target/debug/testls")
    parser.add_argument("--testssl-dir", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("openssl"))
    parser.add_argument("--bash", type=Path, default=Path("/bin/bash"))
    parser.add_argument("--ca", type=Path, default=ROOT / "tests/servers/ca.pem")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--testls-budget", type=positive_seconds, default=600)
    parser.add_argument("--comparator-budget", type=positive_seconds, default=900)
    args = parser.parse_args()
    previous_umask = os.umask(0o077)
    try:
        body = json_bytes(args.manifest)
        args.manifest_sha256 = hashlib.sha256(body).hexdigest()
        data = manifest(args.manifest, args.fixture, body=body)
        if args.mode == "plan":
            planned = []
            for item in data["fixtures"]:
                ours, theirs = commands(item, args, args.testssl_dir)
                destination = (args.output or Path("OUTPUT")).resolve()
                theirs += ["--jsonfile", str(destination / f"{item['name']}.testssl.json"),
                           f"localhost:{item['port']}"]
                planned.append({"name": item["name"], "testls": ours, "comparator": theirs})
            print(json.dumps({"manifest": data, "commands": planned}, indent=2))
            return 0
        if args.output is None:
            raise ValueError("run requires a new --output directory")
        return run_audit(args, data)
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as error:
        print(f"audit error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("audit interrupted; owned scanner processes stopped", file=sys.stderr)
        return 2
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
