from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Callable
from urllib.parse import urlparse


PHASE_CONFIG = {
    "A": {"max_tokens": 8000, "thinking": False},
    "B": {"max_tokens": 8000, "thinking": False},
    "C": {"max_tokens": 500, "thinking": False},
}


class ModelCallError(RuntimeError):
    """Final model-call failure with sanitized details for every attempt."""

    def __init__(self, phase: str, attempts: list[dict[str, Any]]) -> None:
        self.phase = phase
        self.attempts = tuple(dict(item) for item in attempts)
        last = attempts[-1]
        context = []
        if last.get("status_code") is not None:
            context.append(f"HTTP {last['status_code']}")
        if last.get("request_id"):
            context.append(f"request_id={last['request_id']}")
        suffix = f" ({', '.join(context)})" if context else ""
        super().__init__(
            f"phase {phase} failed after {len(attempts)} attempts; "
            f"last error: {last['error_type']}: {last['message']}{suffix}"
        )


class OpenAIJsonModel:
    """Small boundary around an OpenAI-compatible chat completion API."""

    def __init__(
        self,
        client: Any,
        model: str,
        *,
        max_attempts: int = 3,
        temperature: float = 0.2,
        error_reporter: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.client = client
        self.model = model
        self.max_attempts = max_attempts
        self.temperature = temperature
        self.error_reporter = error_reporter

    @classmethod
    def from_env(cls) -> "OpenAIJsonModel":
        settings = {
            "LLM_API_KEY": os.environ.get("LLM_API_KEY", "").strip(),
            "LLM_BASE_URL": os.environ.get("LLM_BASE_URL", "").strip(),
            "LLM_MODEL": os.environ.get("LLM_MODEL", "").strip(),
        }
        missing = [name for name, value in settings.items() if not value]
        if missing:
            raise ValueError(f"missing environment settings: {', '.join(missing)}")
        _validate_base_url(settings["LLM_BASE_URL"])

        from openai import OpenAI

        client = OpenAI(
            api_key=settings["LLM_API_KEY"],
            base_url=settings["LLM_BASE_URL"],
            timeout=120.0,
            max_retries=0,
        )
        return cls(
            client=client,
            model=settings["LLM_MODEL"],
            error_reporter=_print_attempt_error,
        )

    def complete_json(self, system_prompt: str, user_prompt: str, phase: str) -> dict:
        if phase not in PHASE_CONFIG:
            raise ValueError(f"unknown phase {phase!r}")
        config = PHASE_CONFIG[phase]
        last_error: Exception | None = None
        attempt_errors: list[dict[str, Any]] = []
        for attempt in range(1, self.max_attempts + 1):
            response_content: str | None = None
            finish_reason: str | None = None
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.temperature,
                    max_tokens=config["max_tokens"],
                    response_format={"type": "json_object"},
                    extra_body={
                        "thinking": {
                            "type": "enabled" if config["thinking"] else "disabled"
                        }
                    },
                )
                choice = response.choices[0]
                finish_reason = choice.finish_reason
                if finish_reason == "length":
                    raise ValueError("model output was truncated")
                response_content = choice.message.content or ""
                json_payload = _unwrap_json_code_fence(response_content)
                value = _load_model_json(json_payload)
                if not isinstance(value, dict):
                    raise ValueError("model output must be a JSON object")
                return value
            except (json.JSONDecodeError, IndexError, AttributeError, ValueError) as error:
                last_error = error
            except Exception as error:
                last_error = error
            if last_error is None:
                raise AssertionError("model call failed without an exception")
            detail = _describe_attempt_error(
                last_error,
                attempt,
                self.max_attempts,
                phase=phase,
                model=self.model,
                base_url=getattr(self.client, "base_url", None),
                model_output=response_content,
                finish_reason=finish_reason,
            )
            attempt_errors.append(detail)
            if self.error_reporter is not None:
                try:
                    self.error_reporter(dict(detail))
                except Exception:
                    pass
            if attempt < self.max_attempts:
                time.sleep(2 ** (attempt - 1))
        raise ModelCallError(phase, attempt_errors) from last_error


def _describe_attempt_error(
    error: Exception,
    attempt: int,
    max_attempts: int,
    *,
    phase: str,
    model: str,
    base_url: Any,
    model_output: str | None,
    finish_reason: str | None,
) -> dict[str, Any]:
    response = getattr(error, "response", None)
    status_code = getattr(error, "status_code", None)
    if status_code is None and response is not None:
        status_code = getattr(response, "status_code", None)

    request_id = getattr(error, "request_id", None)
    if not request_id and response is not None:
        headers = getattr(response, "headers", {}) or {}
        request_id = headers.get("x-request-id") or headers.get("request-id")

    return {
        "phase": phase,
        "model": model,
        "base_url": _safe_base_url(base_url) if base_url else None,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "error_type": type(error).__name__,
        "message": _safe_diagnostic_text(error, limit=2000),
        "status_code": status_code,
        "request_id": _safe_diagnostic_text(request_id, limit=500)
        if request_id
        else None,
        "response_body": _response_body(response),
        "finish_reason": finish_reason,
        "model_output": _safe_diagnostic_text(model_output, limit=4000)
        if model_output is not None
        else None,
    }


def _response_body(response: Any) -> str | None:
    if response is None:
        return None
    body: Any = None
    try:
        body = response.json()
    except Exception:
        body = getattr(response, "text", None)
    if body is None:
        return None
    if not isinstance(body, str):
        try:
            body = json.dumps(body, ensure_ascii=False)
        except (TypeError, ValueError):
            body = str(body)
    return _safe_diagnostic_text(body, limit=4000)


def _unwrap_json_code_fence(content: str) -> str:
    stripped = content.strip().lstrip("\ufeff")
    fenced = re.fullmatch(
        r"```(?:json)?[ \t\r\n]+(?P<body>.*?)\s*```",
        stripped,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return fenced.group("body").strip() if fenced else stripped


def _load_model_json(payload: str) -> Any:
    """Decode JSON with narrowly scoped repairs for common model formatting errors."""
    try:
        return json.loads(payload, parse_constant=_reject_constant)
    except json.JSONDecodeError as original_error:
        repaired = _remove_trailing_commas(payload)
        for candidate in (repaired, _close_unterminated_containers(repaired)):
            if candidate == payload:
                continue
            try:
                return json.loads(candidate, parse_constant=_reject_constant)
            except json.JSONDecodeError:
                pass
        try:
            return _load_last_concatenated_json_value(repaired)
        except json.JSONDecodeError:
            raise original_error


def _remove_trailing_commas(payload: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False

    for index, character in enumerate(payload):
        if in_string:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
            result.append(character)
            continue

        if character == ",":
            next_index = index + 1
            while next_index < len(payload) and payload[next_index].isspace():
                next_index += 1
            if next_index < len(payload) and payload[next_index] in "}]":
                continue

        result.append(character)

    return "".join(result)


def _close_unterminated_containers(payload: str) -> str:
    expected_closers: list[str] = []
    in_string = False
    escaped = False

    for character in payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
        elif character == "{":
            expected_closers.append("}")
        elif character == "[":
            expected_closers.append("]")
        elif character in "}]":
            if not expected_closers or expected_closers.pop() != character:
                return payload

    if in_string or not expected_closers:
        return payload
    return payload + "".join(reversed(expected_closers))


def _load_last_concatenated_json_value(payload: str) -> Any:
    decoder = json.JSONDecoder(parse_constant=_reject_constant)
    values: list[Any] = []
    position = 0
    while position < len(payload):
        while position < len(payload) and payload[position].isspace():
            position += 1
        if position == len(payload):
            break
        value, position = decoder.raw_decode(payload, position)
        values.append(value)
    if len(values) < 2:
        raise json.JSONDecodeError("not concatenated JSON", payload, 0)
    return values[-1]


def _safe_diagnostic_text(value: Any, *, limit: int) -> str:
    text = " ".join(str(value).split()) or "no error message"
    text = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]+", "sk-[REDACTED]", text)
    text = re.sub(
        r'(?i)(["\']?(?:api[_-]?key|access[_-]?token|authorization)["\']?\s*[:=]\s*["\']?)[^"\'\s,;}]+',
        r"\1[REDACTED]",
        text,
    )
    return text[:limit]


def _safe_base_url(value: Any) -> str:
    parsed = urlparse(str(value))
    if not parsed.scheme or not parsed.hostname:
        return "[invalid base URL]"
    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    return parsed._replace(
        netloc=hostname + port,
        query="",
        fragment="",
    ).geturl()


def _print_attempt_error(detail: dict[str, Any]) -> None:
    context = []
    if detail.get("base_url"):
        context.append(f"base_url={detail['base_url']}")
    if detail.get("status_code") is not None:
        context.append(f"status={detail['status_code']}")
    if detail.get("request_id"):
        context.append(f"request_id={detail['request_id']}")
    suffix = f" {' '.join(context)}" if context else ""
    print(
        f"API ERROR phase={detail['phase']} model={detail['model']} "
        f"attempt={detail['attempt']}/{detail['max_attempts']} "
        f"{detail['error_type']}: {detail['message']}{suffix}",
        file=sys.stderr,
        flush=True,
    )
    if detail.get("response_body"):
        print(
            f"  response_body={detail['response_body']}",
            file=sys.stderr,
            flush=True,
        )
    if detail.get("model_output"):
        print(
            f"  model_output={detail['model_output']}",
            file=sys.stderr,
            flush=True,
        )


def _validate_base_url(value: str) -> None:
    parsed = urlparse(value)
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "https" and parsed.netloc:
        return
    if parsed.scheme == "http" and parsed.hostname in local_hosts:
        return
    raise ValueError("LLM_BASE_URL must use HTTPS (HTTP is allowed only for localhost)")


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
