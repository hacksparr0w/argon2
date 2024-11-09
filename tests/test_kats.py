from typing import Any, Dict

import argon2
import pytest


@pytest.mark.parametrize(
    "params",
    [
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                96 a9 d4 e5 a1 73 40 92 c8 5e 29 f4 10 a4 59 14
                a5 dd 1f 5c bf 08 b2 67 0d a6 8a 02 85 ab f3 2b
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.D,
            "version": argon2.Argon2Version.V10
        },
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                87 ae ed d6 51 7a b8 30 cd 97 65 cd 82 31 ab b2
                e6 47 a5 de e0 8f 7c 05 e0 2f cb 76 33 35 d0 fd
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.I,
            "version": argon2.Argon2Version.V10
        },
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                b6 46 15 f0 77 89 b6 6b 64 5b 67 ee 9e d3 b3 77
                ae 35 0b 6b fc bb 0f c9 51 41 ea 8f 32 26 13 c0
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.ID,
            "version": argon2.Argon2Version.V10
        },
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                51 2b 39 1b 6f 11 62 97 53 71 d3 09 19 73 42 94
                f8 68 e3 be 39 84 f3 c1 a1 3a 4d b9 fa be 4a cb
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.D,
            "version": argon2.Argon2Version.V13
        },
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                c8 14 d9 d1 dc 7f 37 aa 13 f0 d7 7f 24 94 bd a1
                c8 de 6b 01 6d d3 88 d2 99 52 a4 c4 67 2b 6c e8
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.I,
            "version": argon2.Argon2Version.V13
        },
        {
            "password": (
                """
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
                """
            ),
            "salt": (
                """
                02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
                """
            ),
            "secret": (
                """
                03 03 03 03 03 03 03 03
                """
            ),
            "ad": (
                """
                04 04 04 04 04 04 04 04 04 04 04 04
                """
            ),
            "hash": (
                """
                0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
                d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
                """
            ),
            "memory": 32,
            "iterations": 3,
            "parallelism": 4,
            "length": 32,
            "variant": argon2.Argon2Variant.ID,
            "version": argon2.Argon2Version.V13
        }
    ]
)
def test(params: Dict[str, Any]) -> None:
    params["password"] = bytes.fromhex(params["password"])
    params["salt"] = bytes.fromhex(params["salt"])
    params["secret"] = bytes.fromhex(params["secret"])
    params["ad"] = bytes.fromhex(params["ad"])
    params["hash"] = bytes.fromhex(params["hash"])

    assert argon2.argon2_verify(**params)
