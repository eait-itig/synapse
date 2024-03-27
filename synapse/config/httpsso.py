#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2021 The Matrix.org Foundation C.I.C.
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright (C) 2023 New Vector, Ltd
# Copyright 2024 The University of Queensland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#

from typing import Any, List

from synapse.config.sso import SsoAttributeRequirement
from synapse.types import JsonDict

from ._base import Config, ConfigError
from ._util import validate_config


class HttpSsoConfig(Config):
    """HTTP header SSO Configuration"""

    section = "httpsso"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        httpsso_config = config.get("httpsso_config", None)
        self.httpsso_enabled = httpsso_config and httpsso_config.get("enabled", True)

        if self.httpsso_enabled:
            self.httpsso_json_header = httpsso_config.get('json_header', 'x-kvd-payload')

            public_baseurl = self.root.server.public_baseurl
            self.httpsso_service_url = public_baseurl + "_matrix/client/r0/login/httpsso"

            self.httpsso_enable_registration = httpsso_config.get('enable_registration', True)

            self.idp_name = httpsso_config.get("idp_name", "SSO")
            self.idp_icon = httpsso_config.get("idp_icon")
            self.idp_brand = httpsso_config.get("idp_brand")

        else:
            self.httpsso_json_header = None
            self.httpsso_service_url = None


# CAS uses a legacy required attributes mapping, not the one provided by
# SsoAttributeRequirement.
REQUIRED_ATTRIBUTES_SCHEMA = {
    "type": "object",
    "additionalProperties": {"anyOf": [{"type": "string"}, {"type": "null"}]},
}


def _parsed_required_attributes_def(
    required_attributes: Any,
) -> List[SsoAttributeRequirement]:
    validate_config(
        REQUIRED_ATTRIBUTES_SCHEMA,
        required_attributes,
        config_path=("httpsso_config", "required_attributes"),
    )
    return [SsoAttributeRequirement(k, v) for k, v in required_attributes.items()]
