# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from typing import Any

from . import exceptions as exceptions
from .exceptions import (
    DecodeError as DecodeError,
)
from .exceptions import (
    ExpiredSignatureError as ExpiredSignatureError,
)
from .exceptions import (
    InvalidAlgorithmError as InvalidAlgorithmError,
)
from .exceptions import (
    InvalidSignatureError as InvalidSignatureError,
)
from .exceptions import (
    PyJWTError as PyJWTError,
)

class PyJWK:
    key: Any

class PyJWKClientError(Exception): ...

class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = ...,
        max_cached_keys: int = ...,
    ) -> None: ...
    def get_signing_key_from_jwt(self, token: str) -> PyJWK: ...

def get_unverified_header(jwt: str) -> dict[str, Any]: ...
def encode(payload: dict[str, Any], key: Any, algorithm: str | None = ...) -> str: ...
def decode(
    jwt: str,
    key: Any,
    algorithms: list[str],
    options: dict[str, Any] | None = ...,
    audience: str | list[str] | None = ...,
    issuer: str | None = ...,
    leeway: float = ...,
) -> dict[str, Any]: ...
