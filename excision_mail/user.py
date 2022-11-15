import typing

from .UserManager import UserManager, UStat
from .utils import get_newpass


def user_add(user: str, **kwargs):
    um = UserManager(**kwargs)
    newpass = get_newpass()
    um.user_add(user, newpass)


def user_delete(user: str, **kwargs):
    um = UserManager(**kwargs)
    um.user_delete(user)


def user_disable(user: str, **kwargs):
    um = UserManager(**kwargs)
    um.user_disable(user)


def user_enable(user: str, **kwargs):
    um = UserManager(**kwargs)
    um.user_enable(user)


def alias_add(alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_add(alias)


def alias_allow(user: str, alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_allow(user, alias)


def alias_delete(alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_delete(alias)


def alias_deny(user: str, alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_deny(user, alias)


def alias_disable(alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_disable(alias)


def alias_enable(alias: str, **kwargs):
    um = UserManager(**kwargs)
    um.alias_enable(alias)


def change_passwd(user: str, **kwargs):
    um = UserManager(**kwargs)
    newpass = get_newpass()
    um.change_passwd(user, newpass)


def account_info(account: str, **kwargs):
    um = UserManager(**kwargs)
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
        print(f'{account} is not present')
    else:
        print(f'{account} status unknown')
