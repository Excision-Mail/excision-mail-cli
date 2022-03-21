import typing

from .UserManager import UserManager, UStat
from .utils import get_newpass


def user_add(user: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    newpass = get_newpass()
    um.user_add(user, newpass)


def user_delete(user: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.user_delete(user)


def user_disable(user: str, config: typing.Dict[str, str], *args, **kwargs):
    um = UserManager(**config)
    um.user_disable(user)


def user_enable(user: str, config: typing.Dict[str, str], *args, **kwargs):
    um = UserManager(**config)
    um.user_enable(user)


def alias_add(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.alias_add(alias)


def alias_allow(user: str, alias: str, config: typing.Dict[str, str], *_,
                **__):
    um = UserManager(**config)
    um.alias_allow(user, alias)


def alias_delete(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.alias_delete(alias)


def alias_deny(user: str, alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.alias_deny(user, alias)


def alias_disable(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.alias_disable(alias)


def alias_enable(alias: str, config: typing.Dict[str, str], *_, **__):
    um = UserManager(**config)
    um.alias_enable(alias)


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
