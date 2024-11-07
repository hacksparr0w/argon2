import ctypes
import sys

from pathlib import Path
from typing import Literal, Optional, TypeAlias


__all__ = (
    "Argon2Error",
    "Argon2Variant",

    "argon2",
    "argon2_verify"
)


def _load_library() -> ctypes.CDLL:
    directory = Path(__file__).parent

    if sys.platform == "win32":
        path = directory / "argon2.dll"
    elif sys.platform == "linux":
        path = directory / "libargon2.so"
    else:
        raise RuntimeError("Unsupported platform")

    return ctypes.CDLL(str(path))


_libargon = _load_library()


_allocate_fptr = ctypes.POINTER(
    ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.POINTER(
            ctypes.POINTER(ctypes.c_uint8)
        ),
        ctypes.c_size_t
    )
)


_deallocate_fptr = ctypes.POINTER(
    ctypes.CFUNCTYPE(
        None,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t
    )
)


class _Argon2Context(ctypes.Structure):
    _fields_ = [
        ("out", ctypes.POINTER(ctypes.c_uint8)),
        ("outlen", ctypes.c_uint32),

        ("pwd", ctypes.POINTER(ctypes.c_uint8)),
        ("pwdlen", ctypes.c_uint32),

        ("salt", ctypes.POINTER(ctypes.c_uint8)),
        ("saltlen", ctypes.c_uint32),

        ("secret", ctypes.POINTER(ctypes.c_uint8)),
        ("secretlen", ctypes.c_uint32),

        ("ad", ctypes.POINTER(ctypes.c_uint8)),
        ("adlen", ctypes.c_uint32),

        ("t_cost", ctypes.c_uint32),
        ("m_cost", ctypes.c_uint32),
        ("lanes", ctypes.c_uint32),
        ("threads", ctypes.c_uint32),

        ("version", ctypes.c_uint32),

        ("allocate_cbk", _allocate_fptr),
        ("deallocate_cbk", _deallocate_fptr),

        ("flags", ctypes.c_uint32)
    ]


class _Argon2Type(ctypes.c_int):
    ARGON2_D = 0
    ARGON2_I = 1
    ARGON2_ID = 2


Argon2Variant: TypeAlias = Literal["d", "i", "id"]


def _build_ctx(
    *,
    output_buffer,
    output_length: int,
    password: bytes,
    salt: Optional[bytes],
    secret: Optional[bytes],
    ad: Optional[bytes],
    iterations: int,
    memory: int,
    parallelism: int
) -> _Argon2Context:
    password_length = len(password)
    password_buffer = (ctypes.c_uint8 * password_length) \
        .from_buffer_copy(password)

    salt_length = len(salt) if salt is not None else 0
    salt_buffer = (ctypes.c_uint8 * salt_length) \
        .from_buffer_copy(salt) if salt is not None else None

    secret_length = len(secret) if secret is not None else 0
    secret_buffer = (ctypes.c_uint8 * secret_length) \
        .from_buffer_copy(secret) if secret is not None else None

    ad_length = len(ad) if ad is not None else 0
    ad_buffer = (ctypes.c_uint8 * ad_length) \
        .from_buffer_copy(ad) if ad is not None else None

    return _Argon2Context(
        out=output_buffer,
        outlen=output_length,
        pwd=password_buffer,
        pwdlen=password_length,
        salt=salt_buffer,
        saltlen=salt_length,
        secret=secret_buffer,
        secretlen=secret_length,
        ad=ad_buffer,
        adlen=ad_length,
        t_cost=iterations,
        m_cost=memory,
        lanes=parallelism,
        threads=parallelism,
        version=0x13,
        allocate_cbk=None,
        deallocate_cbk=None,
        flags=0x00
    )


_libargon.argon2_ctx.restype = ctypes.c_int
_libargon.argon2_ctx.argtypes = [
    ctypes.POINTER(_Argon2Context),
    _Argon2Type
]


_libargon.argon2_error_message.restype = ctypes.c_char_p
_libargon.argon2_error_message.argtypes = [ctypes.c_int]


_libargon.argon2_verify_ctx.restype = ctypes.c_int
_libargon.argon2_verify_ctx.argtypes = [
    ctypes.POINTER(_Argon2Context),
    ctypes.c_char_p,
    _Argon2Type
]


def _get_argon2_error_messages(code: int) -> str:
    return _libargon.argon2_error_message(code).decode("utf-8")


def _get_argon2_type(variant: Argon2Variant) -> int:
    if variant == "d":
        return _Argon2Type.ARGON2_D
    elif variant == "i":
        return _Argon2Type.ARGON2_I
    elif variant == "id":
        return _Argon2Type.ARGON2_ID

    raise ValueError("Invalid variant")


class Argon2Error(Exception):
    def __init__(self, code) -> None:
        super().__init__(_get_argon2_error_messages(code))

        self.code = code


def argon2(
    *,
    password: bytes,
    salt: Optional[bytes],
    secret: Optional[bytes] = None,
    ad: Optional[bytes] = None,
    iterations: int = 4,
    memory: int = 32 * 1000,
    parallelism: int = 1,
    variant: Argon2Variant = "id",
    output_length: int = 32
) -> bytes:
    type = _get_argon2_type(variant)
    output_buffer = (ctypes.c_uint8 * output_length)()
    ctx = _build_ctx(
        output_buffer=output_buffer,
        output_length=output_length,
        password=password,
        salt=salt,
        secret=secret,
        ad=ad,
        iterations=iterations,
        memory=memory,
        parallelism=parallelism
    )

    code = _libargon.argon2_ctx(ctypes.byref(ctx), type)

    if code == 0:
        return bytes(output_buffer)

    raise Argon2Error(code)


def argon2_verify(
    *,
    hash: bytes,
    password: bytes,
    salt: Optional[bytes],
    secret: Optional[bytes] = None,
    ad: Optional[bytes] = None,
    iterations: int = 4,
    memory: int = 32 * 1000,
    parallelism: int = 1,
    variant: Argon2Variant = "id",
    output_length: int = 32
) -> bool:
    type = _get_argon2_type(variant)
    output_buffer = (ctypes.c_uint8 * output_length)()
    ctx = _build_ctx(
        output_buffer=output_buffer,
        output_length=output_length,
        password=password,
        salt=salt,
        secret=secret,
        ad=ad,
        iterations=iterations,
        memory=memory,
        parallelism=parallelism
    )

    code = _libargon.argon2_verify_ctx(
        ctypes.byref(ctx),
        ctypes.c_char_p(hash),
        type
    )

    if code == 0:
        return True
    elif code == -35:
        return False

    raise Argon2Error(code)
