<h1 align="center">
  🔑🛡️ <code>argon2</code>
</h1>

Argon2 is a password-hashing function that summarizes the state of the art in
the design of memory-hard functions and can be used to hash passwords for
credential storage, key derivation, or other applications. This project
provides safe, simple, and efficient Python bindings for the original C
implementation.

## Features

 - ✨ Minimalistic and elegant bindings to the original C implementation.
 - 🚨 Type-safe with sane defaults, clean API, and sensible error handling.
 - ⚙️ Integrated build process that compiles the C library from source for
 all supported platforms.

## Installation

You can install `argon2` using `pip`:

```bash
pip install git+https://github.com/hacksparr0w/argon2.git
```

## Usage

### Python API

#### `argon2.argon2`

```python

def argon2(
    *,
    password: bytes,
    salt: Optional[bytes],
    secret: Optional[bytes] = None,
    ad: Optional[bytes] = None,
    iterations: int = 4,
    memory: int = 8 * 1024 ** 2,
    parallelism: int = 4,
    length: int = 32,
    variant: Argon2Variant = Argon2Variant.ID,
    version: Argon2Version = Argon2Version.V13
) -> bytes:
    ...
```

#### `argon2.argon2_verify`

```python
def argon2_verify(
    *,
    hash: bytes,
    password: bytes,
    salt: Optional[bytes],
    secret: Optional[bytes] = None,
    ad: Optional[bytes] = None,
    iterations: int = 4,
    memory: int = 8 * 1024 ** 2,
    parallelism: int = 4,
    length: int = 32,
    variant: Argon2Variant = Argon2Variant.ID,
    version: Argon2Version = Argon2Version.V13
) -> bool:
    ...
```

## Examples

```python
import argon2

password = b"password"
salt = bytes.fromhex("4ab2ac7e577e297c6475c0fecca9ea55")
hash = argon2.argon2(password=password, salt=salt)
result = argon2.argon2_verify(hash=hash, password=password, salt=salt)
```

## Issues

Found bug or have an idea for a cool feature? Please, open an issue in our
issue tracker. Pull requests are also welcome!
