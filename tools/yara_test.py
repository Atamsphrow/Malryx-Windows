"""Test W0 : yara-python s'installe, compile une règle et matche en mémoire.

Aucun fichier suspect n'est créé : le motif est cherché dans des octets
en mémoire vive uniquement.
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        import yara
    except ImportError as exc:
        print(f"FAIL: import yara impossible ({exc})")
        return 1
    rules = yara.compile(
        source=(
            'rule MalryxW0 { strings: $m = "MALRYX-W0-PROBE" '
            "condition: $m }"
        )
    )
    matches = rules.match(data=b"prefixe MALRYX-W0-PROBE suffixe")
    if not matches or matches[0].rule != "MalryxW0":
        print("FAIL: la règle compilée n'a pas matché")
        return 1
    version = getattr(yara, "__version__", "inconnue")
    print(f"PASS: yara-python {version}, règle compilée et match confirmé")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
