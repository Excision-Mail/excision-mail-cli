import logging
from enum import Enum

import ldap
from obsd_crypt import crypt_newhash

from .config import needed_keys
from .utils import parse_email


class UStat(Enum):
    USER = 0
    ALIAS = 1
    LIST = 2
    EXTERNAL = 3
    ABSENT = 4
    UNKNOWN = 5


class UserManager:

    def __init__(self, *args, **kwargs):
        for kkey in needed_keys:
            setattr(self, kkey, kwargs[kkey])
        logging.debug('Initializing LDAP connection to server at %s',
                      self.ldap_uri)
        self.ldap_conn = ldap.initialize(self.ldap_uri)
        logging.debug('Validating LDAP credentials')
        self.ldap_conn.bind_s(self.ldap_user, self.ldap_passwd)
        logging.debug('Connected')
        self.ldap_cache = dict()

    def __del__(self):
        self.ldap_conn.unbind_s()

    def check_status(self, mail: str = '') -> UStat:
        logging.debug('Checking status for "%s"', mail)
        mail_data = parse_email(mail)

        entries = self.ldap_conn.search_s(self.ldap_base,
                                          ldap.SCOPE_SUBTREE,
                                          'mail={0}'.format(mail),
                                          attrlist=[
                                              'objectClass', 'mail',
                                              'aliasAddress', 'accountStatus',
                                              'listUser', 'aliasUser'
                                          ])
        logging.debug('Number of entries with given address = %d',
                      len(entries))
        if len(entries) == 0:
            return UStat.ABSENT
        if len(entries) > 1:
            return UStat.UNKNOWN

        self.ldap_cache[mail] = entries[0]

        objectClasses = entries[0][1]['objectClass']
        if b'mailUser' in objectClasses:
            return UStat.USER
        elif b'mailAlias' in objectClasses:
            return UStat.ALIAS
        elif b'mailList' in objectClasses:
            return UStat.LIST
        elif b'externalUser' in objectClasses:
            return UStat.EXTERNAL
        return UStat.UNKNOWN

    def add_user(self, user: str, passwd: str):
        logging.debug('Adding user "%s"', user)
        logging.debug('Validating username')
        user_data = parse_email(user)
        logging.debug('Getting user status in system')
        ustatus = self.check_status(user)

        if ustatus != UStat.ABSENT:
            raise ValueError(f'"{user}" already present in the system')

        logging.debug('User not present, continuing to add them')
        logging.debug('Hashing user password')
        pass_hash = crypt_newhash(passwd)
        if pass_hash == '':
            raise ValueError('Could not hash password')
        pass_hash = '{CRYPT}' + pass_hash
        logging.debug('Successfully calculated password hash')

        user_info = [('objectClass', ['mailUser'.encode('UTF-8')]),
                     ('mail', user.encode('UTF-8')),
                     ('userPassword', pass_hash.encode('UTF-8'))]
        logging.debug('Constructing user DN')
        user_dn = self.user_dn_pattern.format(*user_data)
        logging.debug('Inserting with DN "%s"', user_dn)
        self.ldap_conn.add_s(user_dn, user_info)
        logging.debug('Successfully added user "%s"', user)

    def change_passwd(self, user: str, passwd: str):
        logging.debug('Changing password for "%s"', user)
        logging.debug('Validating username')
        user_data = parse_email(user)
        logging.debug('Checking user status in system')
        ustatus = self.check_status(user)

        if ustatus != UStat.USER:
            raise ValueError(f'"{user}" is not a user in the system')

        pass_hash = crypt_newhash(passwd)
        if pass_hash == '':
            raise ValueError('Could not hash password')
        pass_hash = '{CRYPT}' + pass_hash

        user_info = [(ldap.MOD_REPLACE, 'userPassword',
                      pass_hash.encode('UTF-8'))]
        logging.debug('Constructing user DN')
        user_dn = self.user_dn_pattern.format(*user_data)
        self.ldap_conn.modify_s(user_dn, user_info)
        logging.debug('Successfully changed password for "%s"', user)

    def add_alias(self, alias: str):
        logging.debug('Validating alias')
        alias_data = parse_email(alias)
        logging.debug('Checking alias status in system')
        astatus = self.check_status(alias)
        if astatus != UStat.ABSENT:
            raise ValueError(f'"{alias}" is already present in the system')

        logging.debug('Alias not present, continuing to add them')
        memberURL = 'ldap:///{0}??sub?(&(objectClass=mailUser)(aliasAddress={1}))'.format(
            self.ldap_base, alias)
        alias_info = [('objectClass', [b'mailAlias']),
                      ('mail', alias.encode('UTF-8')),
                      ('memberURL', memberURL.encode('UTF-8'))]
        logging.debug('Constructing alias DN')
        alias_dn = self.alias_dn_pattern.format(*alias_data)
        logging.debug('Inserting with DN "%s"', alias_dn)
        self.ldap_conn.add_s(alias_dn, alias_info)
        logging.debug('Successfully added alias entry')

    def allow_alias(self, user: str, alias: str):
        logging.debug('Validating user')
        user_data = parse_email(user)
        logging.debug('Checking user status in system')
        ustatus = self.check_status(user)
        if ustatus != UStat.USER:
            raise ValueError(f'"{user}" is not a user')

        logging.debug('Validating alias')
        alias_data = parse_email(alias)
        logging.debug('Checking alias status in system')
        astatus = self.check_status(alias)
        if astatus != UStat.ALIAS:
            raise ValueError(f'"{alias}" is not an alias')

        user_info = [(ldap.MOD_ADD, 'aliasAddress', alias.encode('UTF-8'))]
        logging.debug('Constructing user DN')
        user_dn = self.user_dn_pattern.format(*user_data)
        self.ldap_conn.modify_s(user_dn, user_info)
        logging.debug('Successfully added alias "%s" for "%s"', alias, user)

    def remove_alias(self, user: str, alias: str):
        logging.debug('Validating user')
        user_data = parse_email(user)
        logging.debug('Checking user status in system')
        ustatus = self.check_status(user)
        if ustatus != UStat.USER:
            raise ValueError(f'"{user}" is not a user')

        logging.debug('Validating alias')
        alias_data = parse_email(alias)
        logging.debug('Checking alias status in system')
        astatus = self.check_status(alias)
        if astatus != UStat.ALIAS:
            raise ValueError(f'"{alias}" is not an alias')

        user_attrs = self.ldap_cache[user][1]
        if 'aliasAddress' not in user_attrs.keys(
        ) or alias not in user_attrs['aliasAddress']:
            logging.debug('"%s" is not used as an alias by "%s"', alias, user)
            return

        user_info = [(ldap.MOD_DELETE, 'aliasAddress', alias.encode('UTF-8'))]
        logging.debug('Constructing user DN')
        user_dn = self.user_dn_pattern.format(*user_data)
        self.ldap_conn.modify_s(user_dn, user_info)
        logging.debug('Successfully removed alias "%s" for "%s"', alias, user)

    def delete_alias(self, alias: str):
        logging.debug('Validating alias')
        alias_data = parse_email(alias)
        logging.debug('Checking alias status in system')
        astatus = self.check_status(alias)
        if astatus != UStat.ALIAS:
            raise ValueError(f'"{alias}" is not an alias')

        logging.debug('Finding users with alias "{alias}"')
        entries = self.ldap_conn.search_s(
            self.ldap_base, ldap.SCOPE_SUBTREE,
            '(&(aliasAddress={0})(objectClass=mailUser))'.format(alias))
        logging.debug('Found %d users', len(entries))
        for ent in entries:
            self.ldap_conn.modify_s(
                ent[0],
                [(ldap.MOD_DELETE, 'aliasAddress', alias.encode('UTF-8'))])
        logging.debug('Removed alias from all users')
        logging.debug('Constructing alias DN')
        alias_dn = self.alias_dn_pattern.format(*alias_data)
        self.ldap_conn.delete_s(alias_dn)
        logging.debug('Successfully deleted alias "%s"', alias)
