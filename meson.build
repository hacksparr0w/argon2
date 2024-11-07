project('argon2', 'c')

py = import('python').find_installation(pure: false)

py.install_sources(
    [
        'argon2/__init__.py',
        'argon2/py.typed'
    ],
    subdir: 'argon2'
)

shared_library(
    'argon2',
    [
        'libargon2/src/blake2/blake2b.c',
        'libargon2/src/argon2.c',
        'libargon2/src/core.c',
        'libargon2/src/encoding.c',
        'libargon2/src/ref.c',
        'libargon2/src/thread.c'
    ],
    include_directories: include_directories(
        'libargon2/include'
    ),
    install: true,
    install_dir: py.get_install_dir() / 'argon2'
)
