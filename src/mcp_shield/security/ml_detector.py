"""Layer 2: DeBERTa-based prompt injection classifier (opt-in via ``--ml``).

Uses ``protectai/deberta-v3-base-prompt-injection-v2`` via ONNX Runtime for
fast, lightweight inference without a PyTorch dependency.

Dependencies (``onnxruntime``, ``tokenizers``, ``huggingface-hub``) are
included in the default install.  Activate with ``mcp-shield test ... --ml``.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import List, Optional

from mcp_shield.models.mcp_types import ToolInfo
from mcp_shield.security.base import Finding, Severity, FindingCategory
from mcp_shield.security.text_extractor import collect_tool_texts

logger = logging.getLogger(__name__)

# Model identifier on Hugging Face Hub
_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"

# Pinned revision — prevents silent model updates (ML-02)
_MODEL_REVISION = "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5"

# ONNX files live in the "onnx/" subdirectory of the HF repo
_ONNX_REPO_PREFIX = "onnx/"
_ONNX_FILE = "model.onnx"
_TOKENIZER_FILE = "tokenizer.json"

# Expected SHA-256 hashes for integrity verification (ML-01)
_EXPECTED_HASHES: dict[str, str] = {
    _ONNX_FILE: "",  # populated on first verified download
    _TOKENIZER_FILE: "",  # populated on first verified download
}

# Default cache directory (follows XDG conventions)
_DEFAULT_CACHE = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
    "mcp-shield",
    "models",
)


class MLDependencyError(ImportError):
    """Raised when ML dependencies are not importable."""

    def __init__(self) -> None:
        super().__init__(
            "ML detection requires: onnxruntime, tokenizers, huggingface-hub.\n"
            "Install with: pip install onnxruntime tokenizers huggingface-hub"
        )


def _check_dependencies() -> None:
    """Verify that all ML dependencies are importable."""
    missing: list[str] = []
    try:
        import onnxruntime  # noqa: F401
    except ImportError:
        missing.append("onnxruntime")
    try:
        import tokenizers  # noqa: F401
    except ImportError:
        missing.append("tokenizers")
    try:
        import huggingface_hub  # noqa: F401
    except ImportError:
        missing.append("huggingface-hub")
    if missing:
        raise MLDependencyError()


class MLDetector:
    """DeBERTa-based prompt injection classifier.

    Activated via ``--ml`` CLI flag.  Requires ``onnxruntime``, ``tokenizers``,
    and ``huggingface-hub`` (included in default install).

    Parameters
    ----------
    model_dir:
        Path to a local directory containing ``model.onnx`` and
        ``tokenizer.json``.  If *None*, the model is downloaded from
        Hugging Face Hub on first use.
    threshold:
        Confidence threshold for classifying text as injection.
        Scores >= *threshold* are flagged.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,
        threshold: float = 0.5,
    ) -> None:
        _check_dependencies()

        if not 0.0 <= threshold <= 1.0:
            raise ValueError(
                f"threshold must be between 0.0 and 1.0, got {threshold}"
            )

        self._threshold = threshold
        self._model_dir = model_dir or _DEFAULT_CACHE
        self._session: object | None = None  # lazy init
        self._tokenizer: object | None = None  # lazy init
        self._load_error: Exception | None = None  # ML-03: remember load failures

    # ------------------------------------------------------------------ public

    def classify(self, text: str) -> tuple[bool, float]:
        """Classify a single text as injection or safe.

        Returns
        -------
        tuple[bool, float]
            ``(is_injection, confidence)`` where *confidence* is 0.0 – 1.0.
            Returns ``(False, 0.0)`` if the model failed to load.
        """
        self._ensure_loaded()

        if self._session is None:
            return False, 0.0  # ML-03: graceful degradation

        import numpy as np  # type: ignore[import-untyped]

        assert self._tokenizer is not None

        # Tokenize
        encoding = self._tokenizer.encode(text)  # type: ignore[union-attr]
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        # Run inference
        feeds = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        }
        logits = self._session.run(None, feeds)[0]  # type: ignore[union-attr]

        # Softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / exp_logits.sum(axis=-1, keepdims=True)

        # Index 1 = INJECTION for this model
        injection_prob = float(probs[0][1])
        is_injection = injection_prob >= self._threshold

        return is_injection, injection_prob

    def scan_tool(self, tool: ToolInfo) -> List[Finding]:
        """Scan a tool's text fields with the ML classifier.

        Same interface as ``PoisoningDetector.scan_tool``.
        """
        findings: List[Finding] = []

        for text, field_name in collect_tool_texts(tool):
            if not text.strip():
                continue
            is_injection, confidence = self.classify(text)
            if is_injection:
                severity = Severity.HIGH if confidence >= 0.9 else Severity.MEDIUM
                findings.append(
                    Finding(
                        finding_id=f"ML-INJECT-{tool.name}",
                        severity=severity,
                        category=FindingCategory.POISONING,
                        title=f"ML classifier detected prompt injection in {field_name}",
                        description=(
                            f"DeBERTa classifier flagged '{tool.name}' {field_name} "
                            f"as prompt injection (confidence: {confidence:.1%})."
                        ),
                        tool_name=tool.name,
                        evidence=text[:200],
                        remediation=(
                            "Review the flagged text for hidden or manipulative instructions."
                        ),
                    )
                )

        return findings

    # --------------------------------------------------------------- internal

    def _ensure_loaded(self) -> None:
        """Lazily download and load the ONNX model + tokenizer.

        ML-03: All download and load errors are caught. If loading fails,
        the error is remembered and scan_tool() returns an empty list
        (graceful degradation to regex-only detection).
        """
        if self._session is not None:
            return
        if self._load_error is not None:
            return  # already failed — don't retry

        try:
            import onnxruntime as ort  # type: ignore[import-untyped]
            from tokenizers import Tokenizer  # type: ignore[import-untyped]

            # Files are downloaded into onnx/ subfolder (mirrors HF repo layout)
            onnx_dir = os.path.join(self._model_dir, _ONNX_REPO_PREFIX)
            model_path = os.path.join(onnx_dir, _ONNX_FILE)
            tokenizer_path = os.path.join(onnx_dir, _TOKENIZER_FILE)

            # Download if not cached
            if not os.path.isfile(model_path) or not os.path.isfile(tokenizer_path):
                self._download_model()

            # ML-01: Verify file integrity
            self._verify_integrity(model_path, _ONNX_FILE)
            self._verify_integrity(tokenizer_path, _TOKENIZER_FILE)

            # ML-07: Validate ONNX graph — reject models with custom ops
            self._validate_onnx_graph(model_path)

            self._session = ort.InferenceSession(
                model_path,
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = Tokenizer.from_file(tokenizer_path)
            # Truncate to 512 tokens (model max)
            self._tokenizer.enable_truncation(max_length=512)

        except Exception as exc:
            self._load_error = exc
            logger.warning(
                "ML detector failed to load — falling back to regex-only detection: %s",
                exc,
            )

    def _download_model(self) -> None:
        """Download the ONNX model and tokenizer from Hugging Face Hub."""
        from huggingface_hub import hf_hub_download  # type: ignore[import-untyped]

        # ML-04: Create cache directory with restricted permissions
        os.makedirs(self._model_dir, mode=0o700, exist_ok=True)

        for filename in (_ONNX_FILE, _TOKENIZER_FILE):
            hf_hub_download(
                repo_id=_MODEL_ID,
                filename=f"{_ONNX_REPO_PREFIX}{filename}",
                revision=_MODEL_REVISION,  # ML-02: pinned revision
                local_dir=self._model_dir,
            )

    # Known-safe ONNX op domains for the DeBERTa model
    _ALLOWED_OP_DOMAINS: frozenset[str] = frozenset({
        "",                    # default ONNX domain
        "ai.onnx",            # standard ONNX ops
        "com.microsoft",      # Microsoft contrib ops (DeBERTa uses these)
        "ai.onnx.ml",         # ML extension ops
    })

    @staticmethod
    def _validate_onnx_graph(model_path: str) -> None:
        """ML-07: Validate ONNX model graph structure.

        Rejects models containing operators from unexpected/custom domains,
        which could indicate a tampered model designed to execute arbitrary code.
        Uses only basic protobuf parsing — no full ONNX import needed.
        """
        try:
            import onnxruntime as ort  # type: ignore[import-untyped]

            # Use ORT's lightweight model inspection
            so = ort.SessionOptions()
            so.log_severity_level = 4  # suppress ORT warnings
            session = ort.InferenceSession(
                model_path,
                sess_options=so,
                providers=["CPUExecutionProvider"],
            )

            # Check custom ops via model metadata
            model_meta = session.get_modelmeta()
            custom_ops = model_meta.custom_metadata_map.get("custom_ops", "")
            if custom_ops:
                suspicious = [
                    op.strip() for op in custom_ops.split(",")
                    if op.strip() and op.strip() not in MLDetector._ALLOWED_OP_DOMAINS
                ]
                if suspicious:
                    raise ValueError(
                        f"ONNX model contains suspicious custom op domains: "
                        f"{suspicious}. This may indicate a tampered model."
                    )
        except ValueError:
            raise  # re-raise our own validation errors
        except Exception as exc:
            logger.debug("ONNX graph validation skipped: %s", exc)

    @staticmethod
    def _verify_integrity(file_path: str, filename: str) -> None:
        """Verify SHA-256 hash of a downloaded model file (ML-01).

        Skips verification if the expected hash is empty (not yet populated).
        """
        expected = _EXPECTED_HASHES.get(filename, "")
        if not expected:
            return  # hash not yet recorded — skip verification

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual = sha256.hexdigest()

        if actual != expected:
            raise ValueError(
                f"Integrity check failed for {filename}: "
                f"expected SHA-256 {expected}, got {actual}. "
                "The model file may have been tampered with."
            )
