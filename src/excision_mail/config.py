import typing

needed_keys = ['ldap_base', 'ldap_uri', 'ldap_user', 'ldap_passwd', 'user_dn_pattern', 'alias_dn_pattern']

def check_conf(config: typing.Dict[str, str]):
    ckeys = config.keys
    for kkey in needed_keys:
        if kkey not in ckeys():
            raise KeyError(f'"{kkey}" is not present in the config file')

