"""Secret encryption at rest."""

from __future__ import annotations

import base64

import pytest

from app.core.config import ConfigError, Settings
from app.core.crypto import (
    PURPOSE_CX_API_KEY,
    PURPOSE_SMTP_PASSWORD,
    DecryptionError,
    SecretBox,
)

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))


def test_roundtrip_preserves_value() -> None:
    box = SecretBox(KEY_A)
    secret = "eyJhbGciOi.some-refresh-token.value"
    token = box.encrypt(secret, purpose=PURPOSE_CX_API_KEY)
    assert box.decrypt(token, purpose=PURPOSE_CX_API_KEY) == secret


def test_ciphertext_does_not_contain_plaintext() -> None:
    box = SecretBox(KEY_A)
    token = box.encrypt("super-secret-api-key", purpose=PURPOSE_CX_API_KEY)
    assert "super-secret-api-key" not in token
    assert token.startswith("v1.")


def test_encryption_is_randomised() -> None:
    box = SecretBox(KEY_A)
    first = box.encrypt("same-value", purpose=PURPOSE_CX_API_KEY)
    second = box.encrypt("same-value", purpose=PURPOSE_CX_API_KEY)
    assert first != second


def test_purpose_is_bound_to_the_ciphertext() -> None:
    """A value written as an API key cannot be read back as an SMTP password."""
    box = SecretBox(KEY_A)
    token = box.encrypt("value", purpose=PURPOSE_CX_API_KEY)
    with pytest.raises(DecryptionError):
        box.decrypt(token, purpose=PURPOSE_SMTP_PASSWORD)


def test_wrong_master_key_cannot_decrypt() -> None:
    token = SecretBox(KEY_A).encrypt("value", purpose=PURPOSE_CX_API_KEY)
    with pytest.raises(DecryptionError, match="master key may have changed"):
        SecretBox(KEY_B).decrypt(token, purpose=PURPOSE_CX_API_KEY)


def test_tampered_ciphertext_is_rejected() -> None:
    box = SecretBox(KEY_A)
    token = box.encrypt("value", purpose=PURPOSE_CX_API_KEY)
    version, nonce, ciphertext = token.split(".")
    flipped = ciphertext[:-4] + ("AAAA" if not ciphertext.endswith("AAAA") else "BBBB")
    with pytest.raises(DecryptionError):
        box.decrypt(f"{version}.{nonce}.{flipped}", purpose=PURPOSE_CX_API_KEY)


@pytest.mark.parametrize("token", ["", "notatoken", "v1.only-two", "v2.abc.def"])
def test_malformed_tokens_raise_decryption_error(token: str) -> None:
    with pytest.raises(DecryptionError):
        SecretBox(KEY_A).decrypt(token, purpose=PURPOSE_CX_API_KEY)


def test_secret_box_requires_32_byte_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        SecretBox(b"too-short")


class TestMasterKeyResolution:
    def test_missing_key_is_a_config_error(self) -> None:
        settings = Settings(master_key=None, master_key_file=None, env="development")
        with pytest.raises(ConfigError, match="No master key configured"):
            settings.master_key_bytes()

    def test_non_base64_key_is_rejected(self) -> None:
        settings = Settings(master_key="not base64!!", env="development")
        with pytest.raises(ConfigError, match="not valid base64"):
            settings.master_key_bytes()

    def test_wrong_length_key_is_rejected(self) -> None:
        settings = Settings(master_key=base64.b64encode(b"short").decode(), env="development")
        with pytest.raises(ConfigError, match="needs exactly 32"):
            settings.master_key_bytes()

    def test_valid_key_is_decoded(self) -> None:
        settings = Settings(master_key=base64.b64encode(KEY_A).decode(), env="development")
        assert settings.master_key_bytes() == KEY_A

    def test_key_file_is_read_and_trimmed(self, tmp_path) -> None:
        key_file = tmp_path / "master.key"
        key_file.write_text(base64.b64encode(KEY_A).decode() + "\n", encoding="utf-8")
        settings = Settings(master_key_file=key_file, env="development")
        assert settings.master_key_bytes() == KEY_A

    def test_missing_key_file_is_reported(self, tmp_path) -> None:
        settings = Settings(master_key_file=tmp_path / "absent.key", env="development")
        with pytest.raises(ConfigError, match="does not exist"):
            settings.master_key_bytes()


def test_production_requires_secure_cookies() -> None:
    with pytest.raises(ConfigError, match="CXCG_COOKIE_SECURE"):
        Settings(env="production", cookie_secure=False)
