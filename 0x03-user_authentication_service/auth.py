#!/usr/bin/env python3
"""
Module for _hash_password function
"""
import bcrypt
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from typing import (
    TypeVar,
    Union
)

from db import DB
from user import User

U = TypeVar(User)


def _hash_password(password: str) -> bytes:
    """
    Function to hash password str and return it in bytes
    Args:
        password (str): pass in str format
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Function to generate uuid and return the str value
    """
    return str(uuid4())


class Auth:
    """Class - Auth to interact with authentication db.
    """

    def __init__(self) -> None:
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Function to register new user, return user object
        Args:
            email (str): email address of new user
            password (str): password of new user
        Return:
            if no user with given email, return new user
            else ValueError
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            usr = self._db.add_user(email, hashed)
            return usr
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Function to validat user credentials, return True if correct
        or False if not
        Args:
            email (str): email of user
            password (str): password of user
        Return:
            True if user credentials are correct, else False
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        passwd = password.encode("utf-8")
        return bcrypt.checkpw(passwd, user_password)

    def create_session(self, email: str) -> Union[None, str]:
        """
        Function to create session_id for existing user, update user's
        session_id attribute
        Args:
            email (str): email address of user
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[None, U]:
        """
        Function to take session_id and return corresponding user, if one exists,
        otherwise return None
        Args:
            session_id (str): user's session id
        Return:
            user object if found, otherwise None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Function to take user_id, destroy the user's session and update
        session_id attribute to None
        Args:
            user_id (int): user id
        Return:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Function to generate reset_token uuid for user of a given email
        Args:
            email (str): email address of user
        Return:
            new reset_token for the given user
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Function to update user's password
        Args:
            reset_token (str): reset_token issued for password reset
            password (str): user's new password
        Return:
            None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)
