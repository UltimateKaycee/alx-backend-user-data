#!/usr/bin/env python3
"""
Module to define hash_password function that returns a hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Function to return a hashed password
    Args:
        password (str): pword to be hashed
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Function to check if password is valid
    Args:
        hashed_password (bytes): hashed pword
        password (str): pword as string
    Return:
        boolean
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
