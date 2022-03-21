import typing

from .UserManager import UserManager, UStat
from .utils import get_newpass


def add_user(user: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    newpass = get_newpass()
    um.add_user(user, newpass)


def disable_user(user: str, config: typing.Dict[str, str], *args, **kwargs):
    um = UserManager(**config)
    um.disable_user(user)


def delete_user(user: str = '', *_, **__):
    um = UserManager(**config)
    um.delete_user(user)


def add_alias(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.add_alias(alias)


def allow_alias(user: str, alias: str, config: typing.Dict[str, str], *_,
                **__):
    um = UserManager(**config)
    um.allow_alias(user, alias)


def disable_alias(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.disable_alias(alias)


def delete_alias(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.delete_alias(alias)


def remove_alias(user: str, alias: str, config: typing.Dict[str, str], *_,
                 **__):
    um = UserManager(**config)
    um.remove_alias(user, alias)


def change_passwd(user: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    newpass = get_newpass()
    um.change_passwd(user, newpass)


def account_info(account: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    astatus = um.check_status(account)

    if astatus == UStat.USER:
        print(f'{account} is a user')
    elif astatus == UStat.ALIAS:
        print(f'{account} is an alias')
    elif astatus == UStat.LIST:
        print(f'{account} is a mailing list')
    elif astatus == UStat.EXTERNAL:
        print(f'{account} is an external user')
    elif astatus == UStat.ABSENT:
        print(f'{acconut} is not present')
    else:
        print(f'{account} status unknown')
