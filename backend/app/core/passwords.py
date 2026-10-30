from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        valid = _password_hasher.verify(stored_hash, password)
        return bool(valid)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    return _password_hasher.check_needs_rehash(stored_hash)
