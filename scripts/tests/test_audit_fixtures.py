"""Independent synthetic audit tests; no external scanner data or network access."""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "audit-fixtures.py"
SPEC = importlib.util.spec_from_file_location("audit_fixtures", SCRIPT)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def sample_testls():
    """Construct minimal schema-v1 data from the project's documented public schema."""
    return {"schema_version": 1,
            "protocols": [{"version": version, "status": "offered" if version == "TLSv1.2"
                           else "not_offered"} for version in AUDIT.PROTOCOLS],
            "ciphers": [{"protocol": "TLSv1.2", "suites": [{"id": "0x002f"}]}],
            "vulnerabilities": [{"id": "heartbleed", "status": "not tested"},
                                {"id": "ccs_injection", "status": "vulnerable"}]}


def sample_external():
    """Construct synthetic public comparator field records, not captured scanner content."""
    return [{"id": identifier, "finding": "offered" if version == "TLSv1.2" else "not offered"}
            for identifier, version in AUDIT.EXTERNAL_PROTOCOLS.items()] + [
                {"id": "cipher-tls1_2_x002f", "hexcode": "0x00,0x2f"},
                {"id": "heartbleed", "finding": "not vulnerable"},
                {"id": "CCS", "finding": "vulnerable"}]


def fixture():
    """Build a patched-Heartbleed fixture with a positive early-CCS control."""
    return {"name": "sample", "port": 14436, "starttls": None, "protocols": ["TLSv1.2"],
            "vulnerabilities": {"heartbleed": "no_positive", "ccs_injection": "vulnerable"}}


class AdapterTests(unittest.TestCase):
    """Verify conservative normalization, comparison and malformed-output handling."""

    def test_agreement_does_not_make_not_tested_safe(self):
        """Allow patched no-positive controls while retaining inconclusive vulnerability notes."""
        row = AUDIT.compare(fixture(), AUDIT.testls_result(sample_testls()),
                            AUDIT.external_result(sample_external()))
        self.assertEqual(row["status"], "agree")
        self.assertTrue(any("heartbleed: inconclusive" in note for note in row["notes"]))

    def test_cipher_difference_is_review_not_proof(self):
        """Compare IANA identifiers, ignoring names, severities and ordering."""
        data = sample_external()
        data.append({"id": "cipher-tls1_2_x0035", "hexcode": "0x00,0x35", "finding": "ignored"})
        row = AUDIT.compare(fixture(), AUDIT.testls_result(sample_testls()), AUDIT.external_result(data))
        self.assertEqual(row["status"], "review")
        self.assertIn("comparator-only 0x0035", row["differences"][0])

    def test_missing_protocol_or_cipher_is_incomplete(self):
        """Do not treat absent, failed or partial sections as empty accepted sets."""
        for data in (sample_external()[1:], sample_external()[:6]):
            with self.subTest(data=data):
                row = AUDIT.compare(fixture(), AUDIT.testls_result(sample_testls()),
                                    AUDIT.external_result(data))
                self.assertEqual(row["status"], "incomplete")

    def test_bad_suite_and_duplicate_measurements_fail_closed(self):
        """Reject malformed suite identifiers, duplicate records and wrong JSON shapes."""
        for data in (sample_external() + [sample_external()[0]], {"scanResult": []},
                     sample_external() + [{"id": "cipher-tls1_2_x0035", "hexcode": "invalid"}],
                     sample_external() + [{"id": "cipher-tls1_2_x0035", "hexcode": "0x00,0x00,0x35"}]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                AUDIT.external_result(data)
        ours = sample_testls()
        ours["ciphers"][0]["suites"].append({"id": "0x002f"})
        with self.assertRaises(ValueError):
            AUDIT.testls_result(ours)
        ours = sample_testls()
        ours["ciphers"][0]["suites"][0]["id"] = "0x00002f"
        with self.assertRaises(ValueError):
            AUDIT.testls_result(ours)

    def test_enumeration_error_overrides_matching_partial_suites(self):
        """A matching partial enumeration is not a successful comparison."""
        ours = sample_testls()
        ours["ciphers"][0]["error"] = "synthetic failure"
        row = AUDIT.compare(fixture(), AUDIT.testls_result(ours),
                            AUDIT.external_result(sample_external()))
        self.assertEqual(row["status"], "incomplete")

    def test_unrecognized_external_verdict_is_inconclusive(self):
        """Do not derive vulnerability negatives from unfamiliar wording or severity."""
        data = sample_external()
        data[-1]["finding"] = "unrecognized response"
        data[-1]["severity"] = "OK"
        row = AUDIT.compare(fixture(), AUDIT.testls_result(sample_testls()), AUDIT.external_result(data))
        self.assertEqual(row["status"], "incomplete")

    def test_positive_and_negative_controls(self):
        """Flag missing positives and unexpected positives independently of scanner parity."""
        for expected, status, outcome in (("vulnerable", "not tested", "incomplete"),
                                          ("vulnerable", "not vulnerable", "review"),
                                          ("no_positive", "vulnerable", "review")):
            ours, item = sample_testls(), fixture()
            ours["vulnerabilities"][1]["status"] = status
            item["vulnerabilities"]["ccs_injection"] = expected
            row = AUDIT.compare(item, AUDIT.testls_result(ours), AUDIT.external_result(sample_external()))
            self.assertEqual(row["status"], outcome)

    def test_protocol_expectations_detect_matching_wrong_configuration(self):
        """Two scanners agreeing does not override the versioned fixture controls."""
        item = fixture()
        item["protocols"].append("TLSv1.3")
        row = AUDIT.compare(item, AUDIT.testls_result(sample_testls()),
                            AUDIT.external_result(sample_external()))
        self.assertEqual(row["status"], "review")

    def test_json_limits_and_duplicates(self):
        """Bound JSON and reject duplicate keys and non-finite constants."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for body in ('{"x":1,"x":2}', '{"x":NaN}', 'x' * 65):
                path.write_text(body)
                with patch.object(AUDIT, "MAX_JSON", 64), self.assertRaises(ValueError):
                    AUDIT.load_json(path)

    def test_comparator_nonzero_exit_can_have_complete_sections(self):
        """Do not apply testls's exit contract to another scanner's dependency warnings."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "external.json"
            path.write_text(json.dumps(sample_external()))
            run = {"exit_code": 8, "timed_out": False}
            self.assertFalse(AUDIT.measurement(path, AUDIT.external_result, run, None)["incomplete"])
            run["timed_out"] = True
            self.assertTrue(AUDIT.measurement(path, AUDIT.external_result, run, None)["incomplete"])

    def test_testls_scan_error_and_malformed_output_remain_incomplete(self):
        """A parseable scan error and a missing file cannot become successful measurements."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "testls.json"
            path.write_text(json.dumps(sample_testls()))
            run = {"exit_code": 2, "timed_out": False}
            self.assertIn("scanner failed", AUDIT.measurement(path, AUDIT.testls_result, run, {0, 1})["incomplete"])
            result = AUDIT.measurement(Path(directory) / "missing", AUDIT.testls_result, run, {0, 1})
            self.assertIn("output absent, malformed or unsupported", result["incomplete"])

    def test_deeply_nested_json_remains_incomplete(self):
        """Reject parser recursion failures without crashing or reporting successful measurements."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000)
            result = AUDIT.measurement(path, AUDIT.external_result,
                                       {"exit_code": 0, "timed_out": False}, None)
            self.assertIn("output absent, malformed or unsupported", result["incomplete"])


class RunnerTests(unittest.TestCase):
    """Test local-only commands, provenance validation and owned-process cleanup."""

    def test_manifest_rejects_unsafe_and_unknown_targets(self):
        """Reject path traversal, arbitrary flags, remote hosts and unknown selections."""
        data = {"schema_version": 1, "comparator": {"tag": "v3.2.5", "revision": "a" * 40},
                "fixtures": [fixture()]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for change in ({"name": "../outside"}, {"host": "example.org"}, {"port": True},
                           {"port": 0}, {"starttls": "--arbitrary"}):
                bad = copy.deepcopy(data)
                bad["fixtures"][0].update(change)
                path.write_text(json.dumps(bad))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    AUDIT.manifest(path, [])
            path.write_text(json.dumps(data))
            self.assertEqual(len(AUDIT.manifest(path, ["sample"])["fixtures"]), 1)
            with self.assertRaises(ValueError):
                AUDIT.manifest(path, ["unknown"])

    def test_commands_use_loopback_and_no_client_simulation(self):
        """Restrict every scan to loopback with the fixture CA and explicit STARTTLS mode."""
        args = argparse.Namespace(testls=Path("/tool/testls"), bash=Path("/bin/bash"),
                                  openssl=Path("/tool/openssl"), ca=Path("/fixture/ca.pem"))
        item = fixture()
        item["starttls"] = "xmpp"
        ours, theirs = AUDIT.commands(item, args, Path("/external checkout"))
        self.assertEqual(ours[-1], "127.0.0.1:14436")
        self.assertIn("--xmpphost", theirs)
        self.assertIn("--intrusive", ours)
        self.assertNotIn("--phone-out", theirs)
        self.assertNotIn("-c", theirs)
        self.assertIn("--openssl", theirs)

    def test_comparator_checkout_cannot_be_inside_repository(self):
        """Keep external implementation outside the repository before invoking any tool."""
        args = argparse.Namespace(testssl_dir=AUDIT.ROOT / "external-comparator")
        with self.assertRaisesRegex(ValueError, "outside this repository"):
            AUDIT.run_audit(args, {"fixtures": [fixture()]})

    def test_capture_separates_output_and_returns_scan_exit(self):
        """Keep stderr out of JSON even when findings cause exit one."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, "-c", "import sys;print('{}');print('warning',file=sys.stderr);sys.exit(1)"]
            result = AUDIT.capture(command, root, root / "out", root / "err", 2)
            self.assertEqual(result["exit_code"], 1)
            self.assertFalse(result["timed_out"])
            self.assertEqual((root / "out").read_text(), "{}\n")
            self.assertIn("warning", (root / "err").read_text())

    @unittest.skipUnless(os.name == "posix", "Unix process groups required")
    def test_timeout_cleans_owned_process_group(self):
        """Terminate a scanner that ignores SIGTERM within the bounded grace period."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, "-c", "import signal,time,os;signal.signal(signal.SIGTERM,signal.SIG_IGN);print(os.getpid(),flush=True);time.sleep(60)"]
            result = AUDIT.capture(command, root, root / "out", root / "err", 1)
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["exit_code"], -signal.SIGKILL)
            pid = int((root / "out").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_fake_process_audit_writes_reports_without_publishing(self):
        """Exercise orchestration and evidence reports with synthetic local scanner processes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ours, theirs = root / "ours", root / "external"
            ours.write_text(f"#!{sys.executable}\nimport json\nprint(json.dumps({sample_testls()!r}))\n")
            ours.chmod(0o700)
            theirs.mkdir()
            (theirs / "testssl.sh").write_text(
                f"#!{sys.executable}\nimport sys,json\nfrom pathlib import Path\n"
                f"Path(sys.argv[sys.argv.index('--jsonfile')+1]).write_text(json.dumps({sample_external()!r}))\n")
            args = argparse.Namespace(testls=ours, testssl_dir=theirs, openssl=Path(sys.executable),
                                      bash=Path(sys.executable), ca=root / "ca", output=root / "output",
                                      manifest=root / "manifest", testls_budget=10, comparator_budget=10)
            with patch.object(AUDIT, "metadata", return_value={"synthetic": True}):
                self.assertEqual(AUDIT.run_audit(args, {"fixtures": [fixture()]}), 0)
            result = json.loads((args.output / "summary.json").read_text())
            self.assertTrue(result["complete_run"])
            self.assertEqual(result["results"][0]["status"], "agree")
            self.assertTrue((args.output / "summary.md").is_file())
            self.assertIn("Run state: completed", (args.output / "summary.md").read_text())
            self.assertEqual(args.output.stat().st_mode & 0o077, 0)
            with self.assertRaises(FileExistsError), patch.object(AUDIT, "metadata", return_value={}):
                AUDIT.run_audit(args, {"fixtures": [fixture()]})

    def test_provenance_rejects_wrong_pin(self):
        """Fail before scanner invocation when an external checkout differs from the manifest."""
        with patch.object(AUDIT, "inspect_tool", side_effect=["/unused", "b" * 40]), self.assertRaises(ValueError):
            AUDIT.metadata(argparse.Namespace(), {"comparator": {"revision": "a" * 40}}, Path("/unused"))

    def test_provenance_rejects_dirty_checkout_and_wrong_tag(self):
        """Require matching tag metadata and pristine external files before executing them."""
        data = {"comparator": {"revision": "a" * 40, "tag": "v3.2.5"}}
        for replies in (["/unused", "a" * 40, "b" * 40],
                        ["/unused", "a" * 40, "a" * 40, " M testssl.sh"]):
            with self.subTest(replies=replies), patch.object(AUDIT, "inspect_tool", side_effect=replies), \
                    self.assertRaises(ValueError):
                AUDIT.metadata(argparse.Namespace(), data, Path("/unused"))

    def test_metadata_records_valid_synthetic_checkout_and_tool_hashes(self):
        """Verify successful provenance using synthetic metadata without an external installation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = (root / "external").resolve()
            external.mkdir()
            (external / "testssl.sh").write_text("synthetic entry script\n")
            ca, config = root / "ca", root / "manifest"
            ca.write_text("synthetic CA\n")
            config.write_text("{}\n")
            args = argparse.Namespace(testls=Path(sys.executable), openssl=Path(sys.executable),
                                      bash=Path(sys.executable), ca=ca, manifest=config)
            replies = [str(external), "a" * 40, "a" * 40, "", "b" * 40, "", "testls fake",
                       "OpenSSL fake", "bash fake"]
            with patch.object(AUDIT, "inspect_tool", side_effect=replies):
                result = AUDIT.metadata(args, {"comparator": {"revision": "a" * 40,
                                                              "tag": "v3.2.5"}}, external)
            self.assertEqual(result["ca_sha256"], AUDIT.digest(ca))
            self.assertEqual(result["testls"]["sha256"], AUDIT.digest(sys.executable))
            self.assertFalse(result["repository_dirty"])

    def test_default_manifest_matches_published_compose_ports(self):
        """Keep the versioned audit target list aligned with loopback fixture publications."""
        data = AUDIT.manifest(AUDIT.ROOT / "tests/servers/audit.json", [])
        compose = (AUDIT.ROOT / "tests/servers/compose.yaml").read_text()
        published = set(AUDIT.re.findall(r"127\.0\.0\.1:(\d+):", compose))
        self.assertEqual({str(item["port"]) for item in data["fixtures"]}, published)

    def test_plan_needs_no_tools_and_contains_complete_targets(self):
        """A preview is side-effect free and includes the actual comparator target/output arguments."""
        result = subprocess.run([sys.executable, str(SCRIPT), "plan", "--fixture", "mysql",
                                 "--testssl-dir", "/nonexistent-checkout"],
                                check=True, capture_output=True, text=True, timeout=10)
        planned = json.loads(result.stdout)["commands"][0]
        self.assertEqual(planned["comparator"][-1], "localhost:13306")
        self.assertEqual(planned["testls"][-1], "127.0.0.1:13306")
        self.assertIn("--jsonfile", planned["comparator"])

    def test_interruption_retains_incomplete_run_report(self):
        """Persist an unfinished report when an owned scanner is interrupted mid-pair."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(testls=Path(sys.executable), testssl_dir=root / "external",
                                      openssl=Path(sys.executable), bash=Path(sys.executable),
                                      ca=root / "ca", output=root / "output", manifest=root / "manifest",
                                      testls_budget=1, comparator_budget=1)
            with patch.object(AUDIT, "metadata", return_value={}), \
                    patch.object(AUDIT, "capture", side_effect=KeyboardInterrupt), \
                    self.assertRaises(KeyboardInterrupt):
                AUDIT.run_audit(args, {"fixtures": [fixture()]})
            result = json.loads((args.output / "summary.json").read_text())
            self.assertFalse(result["complete_run"])
            self.assertEqual(result["results"], [])
            self.assertIn("Run state: unfinished", (args.output / "summary.md").read_text())

    def test_report_drafts_are_unconfirmed_and_contain_no_raw_logs(self):
        """Emit review-only drafts for incomplete scans without publishing or copying descriptions."""
        with tempfile.TemporaryDirectory() as directory:
            row = {"name": "sample", "status": "incomplete", "differences": [],
                   "incomplete": ["protocol unmeasured: TLSv1.2"],
                   "runs": {"testls": {"command": ["/tool with space", "127.0.0.1:14436"]}}}
            AUDIT.reports(Path(directory), {"results": [row]})
            draft = (Path(directory) / "sample.issue-draft.md").read_text()
            self.assertIn("Unconfirmed", draft)
            self.assertIn("Do not publish", draft)
            self.assertIn("'/tool with space'", draft)


if __name__ == "__main__":
    unittest.main()
