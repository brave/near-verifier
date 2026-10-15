# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

class VerifiedReport:
    status: str
    advisory_ids: list[str]
    def to_json(self) -> str: ...

async def get_collateral_and_verify(quote: bytes, pccs_url: str) -> VerifiedReport: ...
