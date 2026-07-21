from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.llm import diagnose_chat_completion, list_llm_models, llm_public_config, save_llm_config
from app.storage import StateStore, default_state


class LLMConfigTests(unittest.TestCase):
    def test_deepseek_json_mode_uses_vendor_response_format(self) -> None:
        captured: dict = {}

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"choices": [{"message": {"content": '{"ok": true}'}}]}

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def post(self, _url: str, *, json: dict, headers: dict):
                captured["body"] = json
                captured["headers"] = headers
                return FakeResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "deepseek",
                    "model": "deepseek-chat",
                    "endpoint": "https://api.deepseek.com/v1",
                    "apiKey": "test-key",
                    "maxTokens": 256,
                    "temperature": 0,
                    "topP": 1,
                    "timeoutMs": 1000,
                },
                [{"role": "user", "content": "返回 JSON"}],
                json_mode=True,
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})

    def test_custom_provider_uses_responses_api_with_reasoning_options(self) -> None:
        captured: dict = {}

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {"output_text": "SecFlow OK"}

        class FakeClient:
            def __init__(self, **_kwargs) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def post(self, url: str, *, json: dict, headers: dict):
                captured["url"] = url
                captured["body"] = json
                captured["headers"] = headers
                return FakeResponse()

        with patch("app.llm.httpx.Client", FakeClient):
            result = diagnose_chat_completion(
                {
                    "provider": "custom",
                    "model": "gpt-5.6-sol",
                    "endpoint": "https://carpool.example",
                    "apiKey": "test-key",
                    "maxTokens": 256,
                    "timeoutMs": 1000,
                    "wireApi": "responses",
                    "reasoningEffort": "xhigh",
                    "disableResponseStorage": True,
                },
                [{"role": "user", "content": "返回 OK"}],
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(captured["url"], "https://carpool.example/responses")
        self.assertEqual(captured["body"]["reasoning"], {"effort": "xhigh"})
        self.assertFalse(captured["body"]["store"])

    def test_fresh_install_has_empty_disabled_llm_configuration(self) -> None:
        config = default_state()["llm"]

        self.assertEqual(config["api_key"], "")
        self.assertFalse(config["enabled"])

    def test_saved_api_key_is_masked_in_public_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                config = save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "sk-test-secret-123456",
                        "enabled": True,
                    }
                )
                public = llm_public_config()

            self.assertTrue(config["has_api_key"])
            self.assertNotIn("sk-test-secret-123456", str(config))
            self.assertNotIn("sk-test-secret-123456", str(public))
            self.assertEqual(public["api_key_masked"], "sk-t********3456")

    def test_provider_switch_does_not_reuse_previous_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                save_llm_config(
                    {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "endpoint": "https://api.openai.com/v1",
                        "api_key": "sk-openai-secret",
                        "enabled": True,
                    }
                )
                config = save_llm_config(
                    {
                        "provider": "claude",
                        "model": "claude-3-5-sonnet-latest",
                        "endpoint": "https://api.anthropic.com/v1",
                        "enabled": True,
                    }
                )

            self.assertEqual(config["provider"], "claude")
            self.assertFalse(config["has_api_key"])

    def test_model_list_without_key_returns_fallback_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            local_store = StateStore(Path(temp_dir) / "state.json")
            with patch("app.llm.store", local_store):
                catalog = list_llm_models(
                    {
                        "provider": "deepseek",
                        "endpoint": "https://api.deepseek.com/v1",
                    }
                )

            self.assertEqual(catalog["provider"], "deepseek")
            self.assertEqual(catalog["source"], "fallback")
            self.assertTrue(catalog["models"])


if __name__ == "__main__":
    unittest.main()
