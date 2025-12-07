"""Sambanova client wrapper and helper for AI chat.

This module will try to use the official Sambanova SDK if it's
installed (``from sambanova import SambaNova``). If the SDK is not
available it falls back to a direct HTTP call to the Sambanova chat
completions REST endpoint.

Usage:
    client = SambanovaClient()
    reply = client.send_message(api_key, "Hello from KeySentinel")

Security:
- Do NOT hardcode API keys in source. Pass keys at runtime or set the
  SAMBANOVA_API_KEY and SAMBANOVA_API_URL environment variables.
"""

from typing import Optional
import os
import json
import importlib

# Try to import official SDK dynamically
try:
    sambanova_mod = importlib.import_module('sambanova')
    SambaNova = getattr(sambanova_mod, 'SambaNova', None)
    _HAS_SDK = SambaNova is not None
except Exception:
    SambaNova = None
    _HAS_SDK = False

# Dynamically import 'requests' to allow environments without it
try:
    requests = importlib.import_module('requests')
except Exception:
    requests = None


class SambanovaClient:
    def __init__(self, api_url: Optional[str] = None, model: str = "Llama-4-Maverick-17B-128E-Instruct"):
        # Allow caller to override endpoint; otherwise read env var or default
        self.api_url = api_url or os.environ.get('SAMBANOVA_API_URL') or 'https://api.sambanova.ai/v1/chat/completions'
        self.model = model

    def _parse_sdk_response(self, resp) -> str:
        """Extract a readable string from the SDK response object."""
        try:
            # Example structure: response.choices[0].message.content
            choices = getattr(resp, 'choices', None)
            if choices and len(choices) > 0:
                first = choices[0]
                message = getattr(first, 'message', None)
                if message is not None:
                    content = getattr(message, 'content', None)
                    if isinstance(content, list):
                        parts = []
                        for c in content:
                            if isinstance(c, dict) and 'text' in c:
                                parts.append(c['text'])
                            elif hasattr(c, 'get') and c.get('text'):
                                parts.append(c.get('text'))
                            else:
                                parts.append(str(c))
                        return "\n".join(parts)
                    return str(content)
                if hasattr(first, 'text'):
                    return str(first.text)
            return str(resp)
        except Exception:
            return str(resp)

    def _parse_http_response(self, data) -> str:
        """Extract a readable reply from the REST JSON response."""
        try:
            if isinstance(data, dict):
                choices = data.get('choices') or []
                if choices:
                    first = choices[0]
                    msg = first.get('message') or {}
                    content = msg.get('content')
                    if isinstance(content, list):
                        texts = []
                        for c in content:
                            if isinstance(c, dict) and 'text' in c:
                                texts.append(c['text'])
                            else:
                                texts.append(str(c))
                        return "\n".join(texts)
                    if isinstance(content, str):
                        return content
                for k in ('reply', 'text', 'output'):
                    if k in data:
                        return str(data[k])
            return json.dumps(data)
        except Exception:
            return str(data)

    def send_message(self, api_key: str, message: str, model: Optional[str] = None, temperature: float = 0.1, top_p: float = 0.1) -> str:
        """Send `message` using the Sambanova SDK if available, otherwise HTTP.

        Parameters:
        - api_key: Sambanova API key (string)
        - message: user text message
        - model: optional model name override
        - temperature/top_p: sampling params

        Returns the model reply as a string, or an error message on failure.
        """
        model = model or self.model

        # First: try SDK path
        if _HAS_SDK and SambaNova is not None:
            try:
                client = SambaNova(api_key=api_key, base_url=os.environ.get('SAMBANOVA_API_URL') or None)
                payload_messages = [{
                    "role": "user",
                    "content": [{"type": "text", "text": message}]
                }]
                resp = client.chat.completions.create(
                    model=model,
                    messages=payload_messages,
                    temperature=temperature,
                    top_p=top_p
                )
                return self._parse_sdk_response(resp)
            except Exception as e:
                sdk_err = f"SDK call failed: {e}"
        else:
            sdk_err = None

        # HTTP fallback
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        payload = {
            'model': model,
            'messages': [{
                'role': 'user',
                'content': [{ 'type': 'text', 'text': message }]
            }],
            'temperature': temperature,
            'top_p': top_p
        }

        url = self.api_url
        try:
            if requests:
                r = requests.post(url, headers=headers, json=payload, timeout=30)
                r.raise_for_status()
                data = r.json()
                parsed = self._parse_http_response(data)
                if sdk_err:
                    return f"(SDK error: {sdk_err})\n{parsed}"
                return parsed
            else:
                from urllib import request as urllib_request
                req = urllib_request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
                with urllib_request.urlopen(req, timeout=30) as resp:
                    resp_data = resp.read()
                    try:
                        data = json.loads(resp_data)
                        parsed = self._parse_http_response(data)
                        if sdk_err:
                            return f"(SDK error: {sdk_err})\n{parsed}"
                        return parsed
                    except Exception:
                        return resp_data.decode('utf-8', errors='replace')
        except Exception as e:
            msg = f"Error calling Sambanova API: {e}"
            if sdk_err:
                msg = f"{msg} (additional SDK error: {sdk_err})"
            return msg
