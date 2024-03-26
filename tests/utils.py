# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from typing import Literal, overload

from synapse.config.homeserver import HomeServerConfig
from synapse.config.server import DEFAULT_ROOM_VERSION

# When debugging a specific test, it's occasionally useful to write the
# DB to disk and query it with the sqlite CLI.
SQLITE_PERSIST_DB = os.environ.get("SYNAPSE_TEST_PERSIST_SQLITE_DB") is not None


@overload
def default_config(name: str, parse: Literal[False] = ...) -> dict[str, object]: ...


@overload
def default_config(name: str, parse: Literal[True]) -> HomeServerConfig: ...


def default_config(
    name: str, parse: bool = False
) -> dict[str, object] | HomeServerConfig:
    """
    Create a reasonable test config.
    """
    config_dict = {
        "server_name": name,
        # Setting this to an empty list turns off federation sending.
        "federation_sender_instances": [],
        "media_store_path": "media",
        # the test signing key is just an arbitrary ed25519 key to keep the config
        # parser happy
        "signing_key": "ed25519 a_lPym qvioDNmfExFBRPgdTU+wtFYKq4JfwFRv7sYVgWvmgJg",
        # Disable trusted key servers, otherwise unit tests might try to actually
        # reach out to matrix.org.
        "trusted_key_servers": [],
        "event_cache_size": 1,
        "enable_registration": True,
        "enable_registration_captcha": False,
        "macaroon_secret_key": "not even a little secret",
        "password_providers": [],
        "worker_app": None,
        "block_non_admin_invites": False,
        "federation_domain_whitelist": None,
        "filter_timeline_limit": 5000,
        "user_directory_search_all_users": False,
        "user_consent_server_notice_content": None,
        "block_events_without_consent_error": None,
        "user_consent_at_registration": False,
        "user_consent_policy_name": "Privacy Policy",
        "media_storage_providers": [],
        "autocreate_auto_join_rooms": True,
        "auto_join_rooms": [],
        "limit_usage_by_mau": False,
        "hs_disabled": False,
        "hs_disabled_message": "",
        "max_mau_value": 50,
        "mau_trial_days": 0,
        "mau_stats_only": False,
        "mau_limits_reserved_threepids": [],
        "admin_contact": None,
        "rc_message": {"per_second": 10000, "burst_count": 10000},
        "rc_registration": {"per_second": 10000, "burst_count": 10000},
        "rc_login": {
            "address": {"per_second": 10000, "burst_count": 10000},
            "account": {"per_second": 10000, "burst_count": 10000},
            "failed_attempts": {"per_second": 10000, "burst_count": 10000},
        },
        "rc_joins": {
            "local": {"per_second": 10000, "burst_count": 10000},
            "remote": {"per_second": 10000, "burst_count": 10000},
        },
        "rc_joins_per_room": {"per_second": 10000, "burst_count": 10000},
        "rc_invites": {
            "per_room": {"per_second": 10000, "burst_count": 10000},
            "per_user": {"per_second": 10000, "burst_count": 10000},
        },
        "rc_3pid_validation": {"per_second": 10000, "burst_count": 10000},
        "saml2_enabled": False,
        "public_baseurl": None,
        "default_identity_server": None,
        "key_refresh_interval": 24 * 60 * 60 * 1000,
        "old_signing_keys": {},
        "tls_fingerprints": [],
        "use_frozen_dicts": False,
        # We need a sane default_room_version, otherwise attempts to create
        # rooms will fail.
        "default_room_version": DEFAULT_ROOM_VERSION,
        # disable user directory updates, because they get done in the
        # background, which upsets the test runner. Setting this to an
        # (obviously) fake worker name disables updating the user directory.
        "update_user_directory_from_worker": "does_not_exist_worker_name",
        "caches": {"global_factor": 1, "sync_response_cache_duration": 0},
        "listeners": [{"port": 0, "type": "http"}],
    }

    if parse:
        config = HomeServerConfig()
        config.parse_config_dict(config_dict, "", "")
        return config

    return config_dict
