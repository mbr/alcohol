#!/usr/bin/env python
# coding=utf8

import passlib.hash
from testscenarios import TestWithScenarios

RECOMMENDED_SCHEMES = ['pbkdf2_sha1',
                       'pbkdf2_sha256',
                       'pbkdf2_sha512',
                       'sha1_crypt',
                       'sha256_crypt',
                       'sha512_crypt']


def generate_scenarios():
    possible_schemes =\
              ['des_crypt', 'bsdi_crypt', 'bigcrypt', 'crypt16',  # archaic
               'md5_crypt', 'bcrypt', 'sha1_crypt', 'sun_md5_crypt',
               'sha256_crypt', 'sha512_crypt',                    # unix
               'apr_md5_crypt', 'phpass', 'pbkdf2_sha1',
               'pbkdf2_sha256', 'pbkdf2_sha512', 'cta_pbkdf2_sha1',
               'dlitz_pbkdf2_sha1', 'scram', 'bsd_nthash',        # modular
               'ldap_md5', 'ldap_sha1', 'ldap_salted_md5',
               'ldap_salted_sha1', 'ldap_bsdi_crypt',
               'ldap_des_crypt', 'ldap_hex_md5', 'ldap_hex_sha1',
               'ldap_pbkdf2_sha1', 'ldap_pbkdf2_sha256',
               'ldap_pbkdf2_sha512', 'ldap_plaintext',
               'ldap_salted_md5', 'ldap_salted_sha1', 'ldap_sha1_crypt',
               'ldap_sha256_crypt', 'ldap_sha512_crypt',
               'atlassian_pbkdf2_sha1', 'fshp', 'roundup_plaintext',  # ldap
               'mssql2000', 'mssql2005', 'mysql323', 'mysql41',
               'postgres_md5', 'oracle10', 'oracle11',              # sqldb
               'lmhash', 'nthash', 'msdcc', 'msdcc2',               # win
               'cisco_pix', 'cisco_type7', 'django_bcrypt',
               'django_des_crypt', 'django_pbkdf2_sha1',
               'django_pbkdf2_sha256', 'django_salted_md5',
               'django_salted_sha1', 'grub_pbkdf2_sha512',
               'hex_md4', 'hex_md5', 'hex_sha1', 'hex_sha256',
               'hex_sha512', 'plaintext'                            # other
              ]
    blacklist = set([
        'scram',       # returns dict
         # theses only hash the first 8 bytes:
        'des_crypt', 'django_des_crypt',
        'bsdi_crypt',
        'crypt16',
        'bigcrypt',
        'bcrypt'  # not recommended - uses only the first 72 bytes of pw
    ])

    # stick to these, as they are tested
    schemes = RECOMMENDED_SCHEMES

    for i in schemes:
        if i in blacklist:
            continue
        hashfunc = getattr(passlib.hash, i)
        if not hasattr(hashfunc, 'default_salt_size'):
            continue
        if not hasattr(hashfunc, 'checksum_size'):
            continue
        yield (i, {'hashfunc_name': i})


class BaseTestCase(TestWithScenarios):
    def shortDescription(self):
        return 'scenario'

    scenarios = list(generate_scenarios())
