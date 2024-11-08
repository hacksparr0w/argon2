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
            "output_length": 32,
            "type": argon2.Argon2Type.D,
            "version": argon2.Argon2Version.V10
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
