"""
Tests for ULPF End-to-End Reusable Pipeline and Cryptographic Provenance.
Covers:
- run_pipeline execution across heterogeneous log formats
- Contextual enrichment and ML classification during pipeline execution
- Sliding-window correlation alerting
- Cryptographic SHA-256 provenance manifest generation
- Deterministic manifest verification and tamper detection
- CLI commands: 'pipeline' and 'verify-manifest'
"""

import json
from pathlib import Path
import pytest

from src.pipeline import (
    run_pipeline,
    generate_manifest,
    verify_manifest,
    verify_manifest_details,
    cli_main,
)
from src.provenance import calculate_file_sha256

SAMPLES_DIR = Path(__file__).parent / "samples"


@pytest.fixture
def temp_output_dir(tmp_path):
    """Fixture providing isolated output directory for test pipeline runs."""
    out_dir = tmp_path / "pipeline_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


class TestEndToEndPipeline:
    """Test full multi-stage pipeline execution."""

    def test_pipeline_cisco_asa(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "cisco_events.jsonl"
        manifest_file = temp_output_dir / "cisco_manifest.json"

        summary = run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            manifest_file=manifest_file,
            enrich=True,
            correlate=False,
            classify=False,
            verbose=False,
        )

        assert summary["total_lines"] > 0
        assert summary["parsed_ok"] > 0
        assert summary["parse_errors"] == 0
        assert summary["schema_errors"] == 0
        assert out_file.exists()
        assert manifest_file.exists()

        # Check line format in output
        lines = out_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == summary["parsed_ok"]
        first_event = json.loads(lines[0])
        assert first_event["format_name"] == "cisco_asa"
        assert "event_uid" in first_event
        assert "record_hash" in first_event
        assert "raw_log" in first_event

    def test_pipeline_with_enrichment_and_ml_classification(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_paloalto.log"
        out_file = temp_output_dir / "paloalto_events.jsonl"
        manifest_file = temp_output_dir / "paloalto_manifest.json"

        summary = run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            manifest_file=manifest_file,
            enrich=True,
            correlate=True,
            classify=True,
            verbose=False,
        )

        assert summary["parsed_ok"] > 0
        assert out_file.exists()

        lines = out_file.read_text(encoding="utf-8").strip().splitlines()
        for line in lines:
            event = json.loads(line)
            # Check ML classification fields
            assert "weak_label" in event
            assert event["weak_label"] in ("attack", "benign", "uncertain")
            assert "label_confidence" in event
            assert 0.0 <= event["label_confidence"] <= 1.0

            # Check contextual enrichment fields
            assert "src_country" in event
            assert "threat_intel_score" in event
            assert "is_malicious" in event

    def test_pipeline_multi_format_samples(self, temp_output_dir):
        """Verify pipeline handles different formats cleanly."""
        formats = [
            ("sample_cef.log", "cef"),
            ("sample_syslog.log", "syslog"),
            ("sample_leef.log", "leef"),
            ("sample_snort.log", "snort"),
        ]

        for sample_name, expected_fmt in formats:
            sample_path = SAMPLES_DIR / sample_name
            out_file = temp_output_dir / f"{sample_name}.jsonl"
            manifest_file = temp_output_dir / f"{sample_name}_manifest.json"

            summary = run_pipeline(
                input_file=sample_path,
                output_file=out_file,
                manifest_file=manifest_file,
                enrich=False,
                correlate=False,
                classify=False,
                verbose=False,
            )

            assert summary["parsed_ok"] > 0, f"Failed for format {expected_fmt}"
            assert out_file.exists()
            assert verify_manifest(manifest_file) is True


class TestProvenanceManifest:
    """Test cryptographic SHA-256 provenance manifest and tamper detection."""

    def test_manifest_structure(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "events.jsonl"
        alerts_file = temp_output_dir / "alerts.jsonl"
        manifest_file = temp_output_dir / "manifest.json"

        summary = run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            alerts_file=alerts_file,
            manifest_file=manifest_file,
            enrich=True,
            correlate=True,
            classify=True,
            verbose=False,
        )

        with manifest_file.open("r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        assert manifest_data["manifest_schema_version"] == "ulpf-provenance-v1.0"
        assert "execution_id" in manifest_data
        assert "generated_at_utc" in manifest_data

        # Hashes
        input_sha256 = manifest_data["input"]["sha256"]
        output_sha256 = manifest_data["outputs"]["canonical_events"]["sha256"]
        assert len(input_sha256) == 64
        assert len(output_sha256) == 64
        assert input_sha256 == calculate_file_sha256(sample_file)
        assert output_sha256 == calculate_file_sha256(out_file)

        # Stages
        stages = manifest_data["pipeline_stages"]
        assert stages["contextual_enrichment"]["enabled"] is True
        assert stages["machine_learning"]["calibrated_inference"] is True
        assert stages["correlation_engine"]["enabled"] is True

    def test_verify_manifest_success(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "events_ok.jsonl"
        manifest_file = temp_output_dir / "manifest_ok.json"

        run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            manifest_file=manifest_file,
            verbose=False,
        )

        valid, errors = verify_manifest_details(manifest_file)
        assert valid is True
        assert errors == []
        assert verify_manifest(manifest_file) is True

    def test_tamper_detection_in_output_file(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "events_tamper.jsonl"
        manifest_file = temp_output_dir / "manifest_tamper.json"

        run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            manifest_file=manifest_file,
            verbose=False,
        )

        # Baseline: valid
        assert verify_manifest(manifest_file) is True

        # Malicious modification: adversary tampers with output event file
        with out_file.open("a", encoding="utf-8") as f:
            f.write("\n{\"tampered\": true}\n")

        # Re-verification must immediately catch tamper
        valid, errors = verify_manifest_details(manifest_file)
        assert valid is False
        assert len(errors) > 0
        assert any("tampered" in err.lower() or "mismatch" in err.lower() for err in errors)
        assert verify_manifest(manifest_file) is False

    def test_tamper_detection_missing_output_file(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "events_deleted.jsonl"
        manifest_file = temp_output_dir / "manifest_deleted.json"

        run_pipeline(
            input_file=sample_file,
            output_file=out_file,
            manifest_file=manifest_file,
            verbose=False,
        )

        # Delete output file
        out_file.unlink()

        valid, errors = verify_manifest_details(manifest_file)
        assert valid is False
        assert any("missing on disk" in err for err in errors)
        assert verify_manifest(manifest_file) is False


class TestCLIPipelineCommands:
    """Test CLI commands for pipeline execution and verification."""

    def test_cli_pipeline_command(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "cli_events.jsonl"
        manifest_file = temp_output_dir / "cli_manifest.json"

        exit_code = cli_main([
            "pipeline",
            "--input", str(sample_file),
            "--output", str(out_file),
            "--manifest", str(manifest_file),
            "--classify",
        ])

        assert exit_code == 0
        assert out_file.exists()
        assert manifest_file.exists()
        assert verify_manifest(manifest_file) is True

    def test_cli_verify_manifest_command(self, temp_output_dir):
        sample_file = SAMPLES_DIR / "sample_cisco_asa.log"
        out_file = temp_output_dir / "cli_events_v.jsonl"
        manifest_file = temp_output_dir / "cli_manifest_v.json"

        cli_main([
            "pipeline",
            "--input", str(sample_file),
            "--output", str(out_file),
            "--manifest", str(manifest_file),
        ])

        # Test valid
        ret = cli_main(["verify-manifest", "--manifest", str(manifest_file)])
        assert ret == 0

        # Tamper output file
        with out_file.open("a", encoding="utf-8") as f:
            f.write("corrupted data\n")

        # Test invalid/tampered
        ret_tampered = cli_main(["verify-manifest", "--manifest", str(manifest_file)])
        assert ret_tampered == 1
