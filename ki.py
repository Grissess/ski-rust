#!/usr/bin/env python3
import argparse
import dbm.gnu
import logging
import re
import subprocess
import sys
import os

log = logging.getLogger()
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
log.addHandler(sh)

class Formatter(logging.Formatter):
    LEVEL_COLORS = {
            logging.CRITICAL: '35',
            logging.ERROR: '31',
            logging.WARNING: '33',
            logging.INFO: '34',
            logging.DEBUG: '36',
    }
    LEVEL_DEFAULT = '1;37;45'

    def format(self, record):
        record.color = self.LEVEL_COLORS.get(record.levelno, self.LEVEL_DEFAULT)
        return super().format(record)

sh.setFormatter(Formatter('\x1b[%(color)sm* \x1b[m%(message)s'))

class FatalException(RuntimeError):
    pass

class BoxError(Exception):
    pass

def fatal(msg):
    log.critical(msg)
    raise FatalException(msg)

def prompt_yn(msg):
    fatal(f'Prompt for {msg!r} with no interaction configured.')

def prompt_yn_interactive(msg):
    if os.environ.get('QUIET'):
        fatal('Interactive prompt in QUIET mode.')
    while True:
        resp = input(f'{msg} Y/N> ').lower()
        if resp[0] == 'y':
            return True
        if resp[0] == 'n':
            return False
        log.warning('Please enter Y or N.')

ski = os.environ.get('SKI', 'ski')
def run_ski(argv, inp = b''):
    res = subprocess.run([ski] + argv, capture_output = True, input = inp)
    log.debug(repr(res))
    res.check_returncode()
    return res.stdout

def sanity_bypass(check):
    varname = f'SANITY_{check}'
    res = bool(os.environ.get(varname))
    if res:
        log.warning(f'Ignoring the previous check because you asked ({varname})')
    else:
        log.info(f'The previous check can be bypassed (with care!) by setting environment variable {varname} to a non-empty value')
    return res

ski_known_version = (0, 1)
def sanity_checks():
    try:
        ver = run_ski(['--version']).decode()
    except subprocess.CalledProcessError:
        log.critical(f"Couldn't run a ski binary.")
        if 'SKI' in os.environ:
            log.critical(f"The specified binary {os.environ['SKI']!r} failed to run.")
        else:
            log.critical(f"Check that ski is in your PATH (presently {os.environ.get('PATH', '')}) or set the SKI environment variable to its path.")
        if not sanity_bypass('NO_SKI'):
            fatal('No ski binary.')
    ver = ver.partition(' ')[2].partition('-')[0].partition('.')
    ver = tuple(map(int, (ver[0], ver[2])))
    if ver[0] != ski_known_version[0]:
        log.critical(f"The ski binary {ski} is of major version {ver[0]}, while this version of ki only supports {ski_known_version[0]}")
        if not sanity_bypass('BAD_SKI_VERSION'):
            fatal('Ski is too new.')
    if ver[1] != ski_known_version[1]:
        log.warning(f"The ski binary {ski} is of minor version {ver[1]}, while this version of ki was designed for {ski_known_version[1]}. If you experience operational issues, make sure your software is up to date.")

valid_id = re.compile(r'.*@.+\..+')
def validate_id(ident, reason = 'Invalid ID.'):
    if not valid_id.fullmatch(ident):
        log.critical(f"Invalid ID {ident!r} specified; valid IDs should be in the format of a plausible email address to avoid collisions.")
        if not sanity_bypass('INVALID_ID'):
            fatal(reason)

ski_urn_re = re.compile(r'urn:ski:([^:]*):.*')
def is_ski_urn(urn, scheme = None):
    if isinstance(urn, bytes): urn = urn.decode()
    mo = ski_urn_re.fullmatch(urn)
    if not mo:
        return False
    if scheme is not None:
        return mo.group(1) == scheme
    return True

def ski_urn_scheme(urn):
    if isinstance(urn, bytes): urn = urn.decode()
    mo = ski_urn_re.fullmatch(urn)
    if not mo:
        return None
    return mo.group(1)

def ski_get_pdk():
    return run_ski(['sym', 'derive'], None).decode().rstrip()

def ski_decrypt(key, data):
    return run_ski(['sym', 'decrypt', '-a', key], data)

def ski_encrypt(key, data):
    return run_ski(['sym', 'encrypt', '-a', key], data)

def ski_sign(key, data):
    return run_ski(['key', 'sign', '-r', key], data).decode().rstrip()

def ski_verify(key, data, sig):
    try:
        run_ski(['key', 'verify', key, sig], data)
    except subprocess.CalledProcessError:
        return False
    else:
        return True

def ski_derive(prvk):
    return run_ski(['key', 'pub', prvk]).decode().rstrip()

def ski_gen():
    return run_ski(['key', 'gen']).decode().rstrip()

def ski_shared_encrypt(prvk, pubk, data):
    return run_ski(['key', 'encrypt', prvk, pubk], data)

def ski_shared_decrypt(prvk, pubk, data):
    return run_ski(['key', 'decrypt', prvk, pubk], data)

def decrypt_key(kd, reason='No reason given.'):
    if isinstance(kd, bytes): kd = kd.decode()
    while is_ski_urn(kd) and ski_urn_scheme(kd) == 'syed':
        log.warning(f'Enter your password ({reason}): ')
        try:
            kd = ski_decrypt(ski_get_pdk().encode(), kd.encode()).decode().rstrip()
        except UnicodeDecodeError:
            raise ValueError('Decode failed--the password was probably incorrect.')
    return kd

def encrypt_key(rk):
    while True:
        log.info('Enter a password for encryption:')
        k1 = ski_encrypt(ski_get_pdk().encode(), rk)
        log.info('Enter it again, to be sure:')
        rk2 = ski_decrypt(ski_get_pdk().encode(), k1)
        if rk == rk2:
            return k1
        log.error("Keys didn't match, try again.")

pubdb = os.environ.get('PUBDB', os.path.expanduser('~/.ski/pub.db'))
privdb = os.environ.get('PRIVDB', os.path.expanduser('~/.ski/priv.db'))
def db_ensure(private = False):
    db = privdb if private else pubdb
    kind = 'Private' if private else 'Public'
    var = 'PRIVDB' if private else 'PUBDB'
    admon = f'(If this is in error, set the environment variable {var} to the correct path.)'
    dn = os.path.dirname(db)
    if not os.path.exists(dn):
        log.info(f'{kind} DB directory {dn!r} does not exist. {admon}')
        if not prompt_yn('Do you want to create it?'):
            fatal(f'Refused to create {kind} DB directory.')
        os.makedirs(dn)
    if not os.path.isfile(db):
        log.info(f'{kind} DB {db!r} does not exist. {admon}')
        if not prompt_yn('Do you want to create it?'):
            fatal(f'Refused to create {kind} DB.')
        with dbm.gnu.open(db, 'c') as d:
            pass
        os.chmod(db, 0o600)
    s = os.stat(db)
    if s.st_uid != os.geteuid():
        log.critical(f"{kind} DB {db!r} isn't owned by you. This is unsafe. {admon}")
        if not sanity_bypass(f'{var}_NOT_OWNED'):
            fatal(f'{kind} DB not owned.')
    if s.st_mode & 0o777 != 0o600:
        log.critical(f"{kind} DB {db!r} has unsafe permissions 0o{s.st_mode & 0o777:o}. {admon}")
        if not sanity_bypass(f'{var}_INSECURE'):
            fatal(f'{kind} DB has insecure permissions.')
    return db

def db_resolve(ident, private = False, reason = 'Resolving {kind} key {ident}', no_decrypt = False):
    kind = 'Private' if private else 'Public'
    with dbm.gnu.open(db_ensure(private), 'r') as db:
        k = db[ident].decode()  # propagate KeyError
    while True:
        if not is_ski_urn(k):
            raise ValueError(f"Ident {ident!r} has bad {kind} key {k!r}")
        scm = ski_urn_scheme(k)
        if scm == 'syed' and not no_decrypt:
            while True:
                try:
                    k = decrypt_key(k, reason.format(ident = ident, kind = kind))
                except Exception:
                    log.error(f'Failed to decrypt {kind} key for {ident!r}')
                except KeyboardInterrupt:
                    log.error(f'Interrupted--assuming the {kind} key for {ident!r} is unusable.')
                    raise KeyError(ident)
                else:
                    break
        else:
            break
    return k

def db_get(*args, default=None, **kwargs):
    try:
        return db_resolve(*args, **kwargs)
    except KeyError:
        return default

def db_list(private = False):
    with dbm.gnu.open(db_ensure(private), 'r') as db:
        return [i.decode() for i in db.keys()]

def db_store(ident, key, with_pub = True, encrypt = True, overwrite = False):
    validate_id(ident, f"Can't store a key with ID {ident!r}.")
    if isinstance(key, str): key = key.encode()
    if not is_ski_urn(key):
        raise ValueError(f"Key {key!r} not a valid ski URN.")
    scm = ski_urn_scheme(key)
    if scm in ('prvk', 'syed'):
        if scm == 'syed':
            log.warning(f"Assuming syed data {key!r} is an encrypted key (if you're not sure, try to decrypt it first)")
        elif encrypt:
            log.info(f"Encrypting key for {ident!r} for storage.")
            if with_pub:
                log.info("You'll need to provide this password again to store the public key.")
            key = encrypt_key(key)
        with dbm.gnu.open(db_ensure(True)) as db:
            ek = db.get(ident)
            if ek == key:
                log.warning(f'Ident {ident!r} already stored; nothing to do.')
            elif ek is not None and not overwrite:
                log.error(f'Refusing to overwrite {ident!r} with different key.')
            else:
                db[ident] = key
                log.info(f'Stored {ident!r} as {key!r}.')
                if ek is not None:
                    log.warning(f'The previous value of {ek!r} was overwritten.')
        if with_pub:
            db_store(ident, ski_derive(decrypt_key(key, f"To store the public key of {ident!r}")))
    elif scm == 'pubk':
        with dbm.gnu.open(db_ensure(False)) as db:
            ek = db.get(ident)
            if ek == key:
                log.warning(f'Ident {ident!r} already stored; nothing to do.')
            elif ek is not None and not overwrite:
                log.error(f'Refusing to overwrite {ident!r} with different key.')
            else:
                db[ident] = key
                log.info(f'Stored {ident!r} as {key!r}.')
                if ek is not None:
                    log.warning(f'The previous value of {ek!r} was overwritten.')
    else:
        log.error(f'Unrecognized key scheme {scm!r}.')
        raise ValueError(key)

def db_remove(ident, private = False, ignore_nonexistent = False):
    kind = 'private' if private else 'public'
    with dbm.gnu.open(db_ensure(private)) as db:
        try:
            del db[ident]
        except dbm.gnu.error:
            log.error(f'Attempted to remove nonexistent ID {ident!r} from {kind} database')
            if not ignore_nonexistent:
                raise
        else:
            log.info(f'Deleted {ident!r} from {kind} database')

class Cert:
    def __init__(self, ident, key, sig):
        self.ident, self.key, self.sig = ident, key, sig

    @classmethod
    def from_str(cls, s):
        if not s.startswith('urn:ki:cert:'):
            raise ValueError(f'Not a valid Ki cert: {s!r}')
        parts = s[len('urn:ki:cert:'):].split(',')
        if len(parts) != 3:
            raise ValueError(f'Not enough parts in cert: {len(parts)} (expected 3)')
        return cls(*parts)

    @classmethod
    def make(cls, ident, key):
        pub = ski_derive(key)
        head = f'urn:ki:cert:{ident},{pub}'.encode()
        sig = ski_sign(key, head)
        return cls(ident, pub, sig)

    def verify(self):
        head = f'urn:ki:cert:{self.ident},{self.key}'.encode()
        return ski_verify(self.key, head, self.sig)

    def __str__(self):
        return f'urn:ki:cert:{self.ident},{self.key},{self.sig}'

class Box:
    def __init__(self, frm, to, content, sig='', enc=False):
        self.frm, self.to, self.content, self.sig, self.enc = frm, to, content, sig, enc

    @classmethod
    def make(cls, frm, to, content, sign=True, encrypt=True):
        kfrm = db_resolve(frm, True, f'For {frm!r}, to make a box')
        kto = db_resolve(to)
        sig = ''
        if sign:
            sig = ski_sign(kfrm, content)
        if encrypt:
            content = ski_shared_encrypt(kfrm, kto, content)
        return cls(frm, to, content, sig, encrypt)

    @classmethod
    def from_bytes(cls, b):
        if not b.startswith(b'urn:ki:box:'):
            raise ValueError('Not a ki box.')
        first, _, rest = b.partition(b'\n')
        parts = first.decode()[len('urn:ki:box:'):].split(',')
        if len(parts) != 4:
            raise ValueError(f'Not an appropriate number of box parts {len(parts)} (expected 4)')
        return cls(parts[0], parts[1], rest, parts[2], parts[3] != '0')

    def __bytes__(self):
        return f'urn:ki:box:{self.frm},{self.to},{self.sig},{1 if self.enc else 0}\n'.encode() + self.content

    def decrypted(self):
        if not self.enc:
            return self.content
        pkf, pkt = db_get(self.frm), db_get(self.to)
        if pkf is None and pkt is None:
            log.error(f'No usable public key for encrypted box; it cannot be decrypted. (IDs: {self.frm!r}, {self.to!r})')
            raise BoxError('No usable public keys')
        prvk, pubk = None, None
        if pkf is not None:
            prvk = db_get(self.to, True, f'For {self.to!r}, to decrypt box from {self.frm!r}')
            if prvk is not None:
                pubk = pkf
        if pubk is None and pkt is not None:
            prvk = db_get(self.frm, True, f'For {self.frm!r}, to decrypt box to {self.to!r}')
            if prvk is not None:
                pubk = pkt
        if prvk is None:
            log.error(f'No usable private key for encrypted box; it cannot be decrypted. (IDs: {self.frm!r}, {self.to!r})')
            raise BoxError('No usable private keys')
        return ski_shared_decrypt(prvk, pubk, self.content)

    def unbox(self):
        if not self.sig:
            log.error("No signature. This can be dangerous to integrity, and isn't allowed by default.")
            if not sanity_bypass('NO_SIG'):
                raise BoxError('No signature')
        plain = self.decrypted()
        if self.sig:
            frmk = db_get(self.frm)
            if frmk is None:
                log.error(f'No usable signing key for {self.frm!r}; the signature cannot be verified.')
                if not sanity_bypass('NO_SIGKEY'):
                    raise BoxError('No usable signing key')
            else:
                if not ski_verify(frmk, plain, self.sig):
                    log.error(f'Signature from {self.frm!r} failed to verify.')
                    if not sanity_bypass('BAD_SIG'):
                        raise BoxError('Bad signature')
                else:
                    log.info(f"Signature from {self.frm!r} verified.")
        return plain

parser = argparse.ArgumentParser(description = f'Ki Python reference implementation for ski {".".join(map(str, ski_known_version))}')
parser.add_argument('--debug', '-d', action='store_true', help='Include (very) verbose debugging information')
parser.add_argument('--quiet', '-q', action='store_true', help="Don't log anything at all (normally it goes to stderr)")
subparser = parser.add_subparsers()

parser_resolve = subparser.add_parser('resolve', description = "Get the key for an identity")
parser_resolve.add_argument('--priv', '-p', action='store_true', help='Resolve private keys (default is public keys)')
parser_resolve.add_argument('id', nargs='+', help='ID(s) to resolve')
def cmd_resolve(args):
    ret = None
    for ident in args.id:
        try:
            print(db_resolve(ident, private = args.priv))
        except Exception:
            log.error(f'Failed to resolve key for {ident!r}')
            ret = 1
    return ret
parser_resolve.set_defaults(func = cmd_resolve)

parser_store = subparser.add_parser('store', description = "Store an identity's key into the databases")
grp = parser_store.add_mutually_exclusive_group()
grp.add_argument('--priv', '-p', action='store_true', help='Expect a private key...')
grp.add_argument('--pub', '-P', action='store_true', help='... or expect a public key (default is to guess based on scheme)')
parser_store.add_argument('--nopub', action='store_true', help="Don't also store a private key's public key in the pubdb")
parser_store.add_argument('--noenc', action='store_true', help="Don't try to encrypt stored private keys")
parser_store.add_argument('--overwrite', action='store_true', help="Overwrite existing keys")
parser_store.add_argument('--read', action='store_true', help="Treat KEY as a filename which will be read")
parser_store.add_argument('id', help='Identity to add')
parser_store.add_argument('key', help='Key of that identity')
def cmd_store(args):
    ret = None
    try:
        k = args.key
        if args.read:
            k = open(k).read().strip()
        if not is_ski_urn(k):
            log.error(f'{k!r} is not a valid ski URN')
            raise ValueError()
        if args.priv and not is_ski_urn(k, 'prvk'):
            log.error(f'{k!r} is not a ski private key')
            raise TypeError()
        if args.pub and not is_ski_urn(k, 'pubk'):
            log.error(f'{k!r} is not a ski public key')
            raise TypeError()
        db_store(
                args.id, k,
                with_pub = not args.nopub,
                encrypt = not args.noenc,
                overwrite = args.overwrite,
        )
    except Exception:
        log.error(f'Failed to store key {k!r}')
        ret = 1
    return ret
parser_store.set_defaults(func = cmd_store)

parser_gen = subparser.add_parser('gen', description = "Create a new key for an identity")
parser_gen.add_argument('--nopub', action='store_true', help="Don't also store the public part in the pubdb")
parser_gen.add_argument('--noenc', action='store_true', help="Don't encrypt the private key")
parser_gen.add_argument('--overwrite', action='store_true', help="Overwrite existing keys")
parser_gen.add_argument('id', help='Identity for which to create a key')
def cmd_gen(args):
    prvk = ski_gen()
    db_store(
            args.id, prvk,
            with_pub = not args.nopub,
            encrypt = not args.noenc,
            overwrite = args.overwrite,
    )
parser_gen.set_defaults(func = cmd_gen)

parser_encrypt_key = subparser.add_parser('encrypt-key', description = "Encrypt a non-encrypted private key")
parser_encrypt_key.add_argument('id', help='ID of the private key to encrypt')
def cmd_encrypt_key(args):
    try:
        k = db_resolve(args.id, True)
    except KeyError:
        log.error(f'Ident {args.id!r} not found.')
        return 1
    if not is_ski_urn(k, 'prvk'):
        log.error(f'Bad scheme {ski_urn_scheme(k)!r} (is it already encrypted?).')
        return 1
    db_store(args.id, encrypt_key(k), with_pub = False, overwrite = True)
parser_encrypt_key.set_defaults(func = cmd_encrypt_key)

parser_decrypt_key = subparser.add_parser('decrypt-key', description = "Decrypt an encrypted private key (and store it as such)")
parser_decrypt_key.add_argument('id', help='ID of the private key to decrypt')
def cmd_decrypt_key(args):
    try:
        k = db_resolve(args.id, True)
    except KeyError:
        log.error(f'Ident {args.id!r} not found.')
        return 1
    if not is_ski_urn(k, 'syed'):
        log.error(f'Bad scheme {ski_urn_scheme(k)!r} (is it already decrypted?).')
        return 1
    db_store(args.id, decrypt_key(k, f'To store the decrypted key for {args.id!r}'), encrypt = False, with_pub = False, overwrite = True)
parser_decrypt_key.set_defaults(func = cmd_decrypt_key)

parser_passwd = subparser.add_parser('passwd', description = "Change the password of an encrypted private key")
parser_passwd.add_argument('id', help='ID of the private key to change the password')
def cmd_passwd(args):
    try:
        k = db_resolve(args.id, True)
    except KeyError:
        log.error(f'Ident {args.id!r} not found.')
        return 1
    if not is_ski_urn(k, 'syed'):
        log.error(f'Bad scheme {ski_urn_scheme(k)!r} (perhaps you just want encrypt-key?).')
        return 1
    db_store(args.id, encrypt_key(decrypt_key(k, f'To change the password for {args.id!r}')), with_pub = False, overwrite = True)

parser_rename = subparser.add_parser('rename', description = "Change the identities of keys in the database")
parser_rename.add_argument('old_id', help='The present identity')
parser_rename.add_argument('new_id', help='The new identity')
def cmd_rename(args):
    pubk = db_get(args.old_id)
    prvk = db_get(args.old_id, True)
    if pubk is None and prvk is None:
        log.error(f'No keys could be found under identity {args.old_id!r}.')
        return 1
    if db_get(args.new_id) is not None or db_get(args.new_id, True) is not None:
        log.error(f'There are some keys under the new identity {args.new_id!r}; if you intend to replace those, remove them first.')
        return 1
    if pubk is not None:
        db_store(args.new_id, pubk)
        db_remove(args.old_id)
    if prvk is not None:
        db_store(args.new_id, prvk, encrypt = False, with_pub = False)
        db_remove(args.old_id, True)
parser_rename.set_defaults(func = cmd_rename)

parser_delete = subparser.add_parser('delete', description = "Delete an identity or some of its keys")
grp = parser_delete.add_mutually_exclusive_group()
grp.add_argument('--priv', '-p', action='store_true', help="Delete only the private key...")
grp.add_argument('--pub', '-P', action='store_true', help="...or delete only the public key (default is both)")
parser_delete.add_argument('id', help='ID of which to delete keys')
def cmd_delete(args):
    both = not (args.priv or args.pub)
    if args.priv or both:
        db_remove(args.id, True,ignore_nonexistent = True)
    if args.pub or both:
        db_remove(args.id, ignore_nonexistent = True)
parser_delete.set_defaults(func = cmd_delete)

parser_cert = subparser.add_parser('cert', description = "Create, verify, and import certificates")
parser_cert.add_argument('--dry', '-d', action='store_true', help="Don't import, just verify")
parser_cert.add_argument('id_or_cert', nargs='+', help="For each cert, verify (and possibly import); for each ID, generate a cert")
def cmd_cert(args):
    for ci in args.id_or_cert:
        try:
            cert = Cert.from_str(ci)
        except ValueError:
            prvk = db_get(ci, True, reason = f'To make a certificate for {ci!r}')
            if prvk is None:
                log.error(f"Couldn't find a private key for identity {ci!r}.")
                continue
            cert = Cert.make(ci, prvk)
            print(str(cert))
        else:
            if not cert.verify():
                log.error(f"Certificate for {cert.ident!r} is not valid.")
                continue
            if args.dry:
                log.info(f"Certificate for {cert.ident!r} is valid, but not stored as you requested.")
            else:
                try:
                    db_store(cert.ident, cert.key)
                except Exception:
                    log.error(f"Failed to store {cert.ident!r} as {cert.key!r}.")
parser_cert.set_defaults(func = cmd_cert)

parser_list = subparser.add_parser('list', description = "List the key databases")
parser_list.add_argument('--priv', '-p', action='store_true', help='List the private database (default is public)')
def cmd_list(args):
    for ent in db_list(args.priv):
        print(ent)
parser_list.set_defaults(func = cmd_list)

parser_export = subparser.add_parser('export', description = "Export database entries")
parser_export.add_argument('--priv', '-p', action='store_true', help='Export from the private database (default public)')
parser_export.add_argument('--output', '-o', default='-', help='Write to this file (fails if it exists) (default stdout)')
parser_export.add_argument('id', nargs='*', help='IDs to export (if none are specified, export all)')
def cmd_export(args):
    ids = args.id
    if not ids:
        ids = db_list(args.priv)
    fo = sys.stdout
    if args.output != '-':
        if os.path.exists(args.output):
            log.error(f'Refusing to overwrite extant file {args.output!r}.')
            return 1
        fo = open(args.output, 'w')
    for ident in ids:
        try:
            print(f'urn:ki:ex:{ident},{db_resolve(ident, args.priv, no_decrypt = True)}', file = fo)
        except KeyError:
            log.warning(f"Couldn't find a key for identity {ident!r}.")
parser_export.set_defaults(func = cmd_export)

parser_import = subparser.add_parser('import', description = "Import database entries")
parser_import.add_argument('file', nargs='?', help='File to read from (default stdin)')
def cmd_import(args):
    fi = sys.stdin
    if args.file:
        fi = open(args.file, 'r')
    for line in fi:
        line = line.strip()
        if not line:
            continue
        if not line.startswith('urn:ki:ex:'):
            log.warning(f'Not a database entry: {line!r}')
            continue
        parts = line[len('urn:ki:ex:'):].split(',')
        if len(parts) != 2:
            log.warning(f'DB entry has wrong number of parts {len(parts)} (expected 2)')
            continue
        try:
            db_store(*parts, encrypt = False, with_pub = False)
        except Exception:
            log.error(f'Failed to store key for {parts[0]}.')
parser_import.set_defaults(func = cmd_import)

parser_box = subparser.add_parser('box', description = "Create a box")
parser_box.add_argument('--to', '-t', help='Recipient ID of this box (also can be set from environment var KI_TO)')
parser_box.add_argument('--from', '-f', help='Sender ID of this box (also can be set from environment var KI_FROM)')
parser_box.add_argument('--output', '-o', default='-', help='File to write the box to (default stdout)')
parser_box.add_argument('--noenc', action='store_true', help="Don't encrypt the box")
parser_box.add_argument('--nosign', action='store_true', help="Don't sign the box")
parser_box.add_argument('file', nargs='?', help='File to read from (default stdin)')
def cmd_box(args):
    if args.noenc and args.nosign:
        log.warning('A box that is unsigned and unencrypted is particularly useless!')
    if args.nosign:
        log.warning('Unsigned boxes are DANGEROUS to integrity, and are not opened by default (without SANITY_NO_SIG)!')
    frm = getattr(args, 'from')
    to = args.to
    if frm is None:
        frm = os.environ.get('KI_FROM')
    if to is None:
        to = os.environ.get('KI_TO')
    if frm is None:
        log.error('No sender specified! Pass either --from/-f or use the KI_FROM environment variable.')
        return 1
    if to is None:
        log.error('No recipient specified! Pass either --to/-t or use the KI_TO environment variable.')
        return 1
    try:
        fi = sys.stdin.buffer
        if args.file:
            fi = open(args.file, 'rb')
    except IOError:
        log.exception('Failed to open files:')
        return 1
    try:
        box = Box.make(frm, to, fi.read(), sign = not args.nosign, encrypt = not args.noenc)
    except Exception:
        log.exception('Failed to make a box:')
        return 1
    try:
        fo = sys.stdout.buffer
        if args.output != '-':
            fo = open(args.output, 'wb')
        fo.write(bytes(box))
    except IOError:
        log.exception('Failed to write out the box:')
        return 1
parser_box.set_defaults(func = cmd_box)

parser_unbox = subparser.add_parser('unbox', description = "Unbox a box")
parser_unbox.add_argument('--output', '-o', default='-', help="Write the box to this file, if successful (default stdout)")
parser_unbox.add_argument('--list', '-l', action='store_true', help="Don't write out the box, just describe its header and validity")
parser_unbox.add_argument('--machine', action='store_true', help='Use a machine-readable --list output')
parser_unbox.add_argument('box', nargs='?', help="File containing the box (default stdin)")
def cmd_unbox(args):
    if args.machine and not args.list:
        log.error('--machine is ineffective without --list/-l.')
        return 1
    fi = sys.stdin.buffer
    if args.box:
        try:
            fi = open(args.box, 'rb')
        except IOError:
            log.exception('Failed to open input box')
            return 1
    try:
        box = Box.from_bytes(fi.read())
        if args.list:
            if args.machine:
                print(f'FROM={box.frm!r}\nTO={box.to!r}\nSIG={box.sig!r}\nENC={1 if box.enc else 0}')
            else:
                log.info(f'Box from {box.frm!r} to {box.to!r}, {"signature "+repr(box.sig) if box.sig else "no signature"}, {"encrypted" if box.enc else "not encrypted"}')
            return 0
        plain = box.unbox()
        fo = sys.stdout.buffer
        if args.output != '-':
            fo = open(args.output, 'wb')
        fo.write(plain)
    except IOError:
        log.exception('Failed to perform IO:')
        return 1
    except BoxError as e:
        log.error(f'Failed to unbox: {e.args[0]}')
        return 1
    except Exception:
        log.exception('Unknown error while unboxing:')
        return 1
parser_unbox.set_defaults(func = cmd_unbox)

def main():
    global prompt_yn
    prompt_yn = prompt_yn_interactive
    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.NOTSET)
    if args.quiet:
        log.removeHandler(sh)
    sanity_checks()
    if not hasattr(args, 'func'):
        parser.print_help()
        exit(1)
    try:
        res = args.func(args)
        if res is not None:
            exit(res)
    except FatalException:
        exit(1)

if __name__ == '__main__':
    main()
