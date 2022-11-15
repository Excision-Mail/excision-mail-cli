import getpass
import typing

from email.headerregistry import Address


def parse_email(addr_spec: str) -> typing.List[str]:
    addr = Address(addr_spec=addr_spec)
    addr_data = [addr.username, addr.domain]
    addr_data.extend(reversed(addr.domain.split('.')))
    return addr_data


def get_newpass() -> str:
    pass1 = getpass.getpass('Password:')
    pass2 = getpass.getpass('Re-enter password:')

    if pass1 != pass2:
        raise ValueError('Passwords do not match')

    return pass1
