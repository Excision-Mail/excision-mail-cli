import logging
import typing

needed_keys = ['ldap_base', 'ldap_uri', 'user_dn_pattern', 'alias_dn_pattern']
optional_keys = ['ldap_user', 'ldap_passwd']


def check_conf(config: typing.Dict[str, str]):
    ckeys = config.keys()
    for kkey in needed_keys:
        if kkey not in ckeys:
            raise KeyError(
                f'Required key "{kkey}" is not present in the config file')
    for kkey in optional_keys:
        if kkey not in ckeys:
            logging.info(
                'Optional key "{kkey}" is not present in the config file')
