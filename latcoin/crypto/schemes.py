from __future__ import annotations

from latcoin.codec.constants import SCHEME_LATTICE_TOY_V1, SCHEME_SIG_V1, SCHEME_STEALTH_V1
from latcoin.crypto.signatures import (
    scheme_id_to_name,
    scheme_name_to_id,
    supported_signature_scheme_ids,
)

SUPPORTED_SIGNATURE_SCHEMES = frozenset(supported_signature_scheme_ids())
SUPPORTED_STEALTH_SCHEMES = frozenset({SCHEME_STEALTH_V1})
DEFAULT_SIGNATURE_SCHEME = SCHEME_SIG_V1
TOY_LATTICE_SIGNATURE_SCHEME = SCHEME_LATTICE_TOY_V1

SCHEME_NAMES = {scheme_id: scheme_id_to_name(scheme_id) for scheme_id in SUPPORTED_SIGNATURE_SCHEMES}
SCHEME_IDS_BY_NAME = {name: scheme_name_to_id(name) for name in SCHEME_NAMES.values()}
