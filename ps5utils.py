'''
PS5-Utils - PS4/PS5 binary analysis helpers for IDA Pro.

Resolves NID-mangled imports to real symbol names using the ps5rs catalog
(data/nids.csv, data/stubs.txt), detects PS4/PS5 SELF containers, extracts the
inner ELF, and reports module dependencies.

Why the NID string scan is the primary resolver rather than a fallback:
every SELF checked from real game dumps declares PT_DYNAMIC but does not store
its bytes - the SELF segment table simply has no entry backing that program
header, so DT_SCE_SYMTAB/JMPREL cannot be walked. The import strings themselves
(NID#libid#modid) do survive in a loaded segment, one xref each, alongside an
'extern' stub slot per import. Scanning for those resolves ~99.8% of imports on
a real title, so the dynamic-table walk is attempted first but is expected to
come up empty on fake-signed dumps.
'''

import ida_kernwin
import ida_funcs
import idaapi
import idautils
import ida_hexrays
import ida_name
import ida_bytes
import ida_segment
import ida_nalt

import os, re, csv, json, struct, subprocess, threading, logging, tempfile
from functools import partial

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------------------------------------------------------- config

DEFAULT_CONFIG = {
    # Empty means "clone into a temp directory" - see repo_root(). Set an
    # explicit path to keep the checkout somewhere permanent instead.
    "repo_path": "",
    "repo_url": "git@github.com:claimore22/ps5rs.git",
    "nids_csv": "data/nids.csv",
    "stubs_txt": "data/stubs.txt",
    "name_template": "{name}",
    "suffix_on_collision": True,
    "rename_extern": True,
    "rename_string_refs": True,
    "comment_original": True,
    "accept_sources": [],
    "report_dir": "ps5utils_reports",
    "unresolved_csv": "unresolved_nids.csv",
    "deps_report": "module_deps.txt",
}

CONFIG_NAME = 'ps5utils_config.json'
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_NAME)


def load_config():
    '''
    Layer ps5utils_config.json over DEFAULT_CONFIG. Unknown and _-prefixed keys
    are ignored; a missing or malformed file falls back to defaults rather than
    raising, so a bad edit never stops the plugin from loading.
    '''
    cfg = dict(DEFAULT_CONFIG)
    if not os.path.exists(CONFIG_PATH):
        logging.info('PS5-Utils: no %s, using built-in defaults', CONFIG_NAME)
        return cfg
    try:
        with open(CONFIG_PATH, 'r') as fh:
            user = json.load(fh)
    except (ValueError, OSError) as e:
        logging.error('PS5-Utils: cannot read %s (%s) - using defaults', CONFIG_PATH, e)
        return cfg
    if not isinstance(user, dict):
        logging.error('PS5-Utils: %s must hold a JSON object - using defaults', CONFIG_NAME)
        return cfg
    for k, v in user.items():
        if k.startswith('_'):
            continue
        if k not in DEFAULT_CONFIG:
            logging.warning('PS5-Utils: ignoring unknown config key %r', k)
            continue
        cfg[k] = v
    return cfg


config = load_config()


def repo_root():
    '''
    The ps5rs checkout.

    An empty repo_path (the default) puts the clone under the system temp
    directory, so a fresh install needs no configuration and nothing is written
    to the user's home. The name is fixed rather than randomized so the checkout
    survives across IDA sessions and only needs cloning once.
    '''
    configured = (config['repo_path'] or '').strip()
    if configured:
        return os.path.expanduser(configured)
    return os.path.join(tempfile.gettempdir(), 'ps5utils-ps5rs')


def repo_file(rel):
    '''
    Resolve a data path against repo_path unless it is already absolute.
    '''
    if os.path.isabs(rel):
        return rel
    return os.path.join(repo_root(), os.path.expanduser(rel))


# ---------------------------------------------------------------- NID codec

# PS5 base64 variant. The final two characters are '+' and '-', NOT '+/', so a
# stock base64 decoder silently produces wrong values on any NID containing '-'.
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"

# 11 base64 chars, then '#' libid '#' modid. The ids are base64 small integers.
NID_RE = re.compile(r'^[A-Za-z0-9+\-]{11}$')
NID_STRING_RE = re.compile(rb'[A-Za-z0-9+\-]{11}#[A-Za-z0-9+\-]{1,3}#[A-Za-z0-9+\-]{1,3}')


def nid_to_u64(nid):
    '''
    Decode an 11-char NID into its 64-bit hash, matching ps5rs merge_nids.py.
    Returns None if the string is not a valid NID.

    The packing is 3 groups: chars 0-3 -> bytes 0-2, chars 4-7 -> bytes 3-5,
    chars 8-10 -> bytes 6-7.
    '''
    if len(nid) != 11:
        return None
    v = []
    for c in nid:
        i = B64.find(c)
        if i < 0:
            return None
        v.append(i)
    b = bytearray(8)
    b[0] = ((v[0] << 2) | (v[1] >> 4)) & 0xFF
    b[1] = (((v[1] & 0x0F) << 4) | (v[2] >> 2)) & 0xFF
    b[2] = (((v[2] & 0x03) << 6) | v[3]) & 0xFF
    b[3] = ((v[4] << 2) | (v[5] >> 4)) & 0xFF
    b[4] = (((v[5] & 0x0F) << 4) | (v[6] >> 2)) & 0xFF
    b[5] = (((v[6] & 0x03) << 6) | v[7]) & 0xFF
    b[6] = ((v[8] << 2) | (v[9] >> 4)) & 0xFF
    b[7] = (((v[9] & 0x0F) << 4) | (v[10] >> 2)) & 0xFF
    return int.from_bytes(b, 'big')


# ---------------------------------------------------------------- catalog

class NidCatalog:
    '''
    NID -> symbol name, loaded from ps5rs data files.

    nids.csv is the primary source (~175k rows, no conflicting names observed).
    stubs.txt is loaded second and fills gaps; its '# libSceFoo' section headers
    also supply library attribution, which the CSV's library column only has for
    about a third of its rows.
    '''

    def __init__(self):
        self.names = {}
        self.library = {}
        self.sources = {}
        self.loaded_from = []

    def load(self):
        self._load_csv(repo_file(config['nids_csv']))
        self._load_stubs(repo_file(config['stubs_txt']))
        return len(self.names)

    def _load_csv(self, path):
        if not os.path.exists(path):
            logging.warning('PS5-Utils: catalog not found: %s', path)
            return
        accept = set(config['accept_sources'] or [])
        n = 0
        try:
            with open(path, newline='', encoding='utf-8') as fh:
                rdr = csv.DictReader(fh)
                for row in rdr:
                    nid = (row.get('nid') or '').strip()
                    name = (row.get('name') or '').strip()
                    if not nid or not name:
                        continue
                    if accept:
                        srcs = set((row.get('sources') or '').split(';'))
                        if not (srcs & accept):
                            continue
                    self.names[nid] = name
                    lib = (row.get('library') or '').strip()
                    if lib:
                        self.library[nid] = lib
                    self.sources[nid] = row.get('sources') or ''
                    n += 1
        except (OSError, csv.Error) as e:
            logging.error('PS5-Utils: failed reading %s - %s', path, e)
            return
        self.loaded_from.append('%s (%d)' % (os.path.basename(path), n))
        logging.info('PS5-Utils: loaded %d NIDs from %s', n, path)

    def _load_stubs(self, path):
        if not os.path.exists(path):
            return
        lib = None
        added = 0
        try:
            with open(path, encoding='utf-8') as fh:
                for line in fh:
                    line = line.rstrip('\n')
                    if line.startswith('#'):
                        lib = line[1:].strip()
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    nid, name = parts[0], parts[1].strip()
                    # library attribution is useful even when the CSV already
                    # supplied the name
                    if lib and nid not in self.library:
                        self.library[nid] = lib
                    if nid not in self.names and name:
                        self.names[nid] = name
                        self.sources.setdefault(nid, 'stubs.txt')
                        added += 1
        except OSError as e:
            logging.error('PS5-Utils: failed reading %s - %s', path, e)
            return
        self.loaded_from.append('%s (+%d)' % (os.path.basename(path), added))
        logging.info('PS5-Utils: +%d NIDs from %s', added, path)

    def resolve(self, nid):
        return self.names.get(nid)


catalog = NidCatalog()


# ---------------------------------------------------------------- SELF / ELF

SELF_PS4_MAGIC = 0x1D3D154F
SELF_PS5_MAGIC = 0xEEF51454
SELF_HEADER_SIZE = 0x20
SELF_ENTRY_SIZE = 0x20

ET_SCE = {0xFE00: 'ET_SCE_EXEC', 0xFE10: 'ET_SCE_DYNEXEC',
          0xFE18: 'ET_SCE_DYNAMIC (PRX)', 0xFE04: 'ET_SCE_RELEXEC'}
PT_SCE_DYNLIBDATA = 0x61000000


class SelfInfo:
    '''
    Parsed identification of a SELF/ELF file on disk.
    '''

    def __init__(self, path):
        self.path = path
        self.platform = None
        self.is_self = False
        self.inner_elf_off = 0
        self.e_type = None
        self.segments = []
        self.phdrs = []
        self.has_dynlibdata = False
        self.dynamic_idx = None
        self.dynamic_covered = False
        self.encrypted = 0
        self.error = None

    def parse(self):
        try:
            with open(self.path, 'rb') as fh:
                d = fh.read()
        except OSError as e:
            self.error = str(e)
            return self
        if len(d) < 0x40:
            self.error = 'file too small'
            return self

        magic = struct.unpack_from('<I', d, 0)[0]
        if magic in (SELF_PS4_MAGIC, SELF_PS5_MAGIC):
            self.is_self = True
            self.platform = 'PS5' if magic == SELF_PS5_MAGIC else 'PS4'
            nseg = struct.unpack_from('<H', d, 0x18)[0]
            for i in range(nseg):
                fl, off, csz, usz = struct.unpack_from('<QQQQ', d, SELF_HEADER_SIZE + i * SELF_ENTRY_SIZE)
                seg = {'flags': fl, 'off': off, 'csz': csz, 'usz': usz,
                       # phdr index is bits 20-31; taking the whole upper word
                       # instead leaves other flag bits in the index and every
                       # segment then fails the bounds check silently
                       'phdr': (fl >> 20) & 0xFFF,
                       'enc': (fl >> 1) & 1, 'cmp': (fl >> 3) & 1}
                self.segments.append(seg)
                if seg['enc'] or seg['cmp']:
                    self.encrypted += 1
            self.inner_elf_off = SELF_HEADER_SIZE + nseg * SELF_ENTRY_SIZE
        elif d[:4] == b'\x7fELF':
            self.platform = 'ELF'
            self.inner_elf_off = 0
        else:
            self.error = 'not a SELF or ELF (magic 0x%08X)' % magic
            return self

        ie = self.inner_elf_off
        if d[ie:ie + 4] != b'\x7fELF':
            self.error = 'no inner ELF at 0x%X' % ie
            return self

        self.e_type = struct.unpack_from('<H', d, ie + 0x10)[0]
        phoff = struct.unpack_from('<Q', d, ie + 0x20)[0]
        phentsize, phnum = struct.unpack_from('<HH', d, ie + 0x36)
        for i in range(phnum):
            o = ie + phoff + i * phentsize
            if o + 56 > len(d):
                break
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, o)
            self.phdrs.append({'type': t, 'flags': fl, 'off': off, 'vaddr': va,
                               'filesz': fsz, 'memsz': msz})
            if t == PT_SCE_DYNLIBDATA:
                self.has_dynlibdata = True
            if t == 2:
                self.dynamic_idx = i
        covered = {s['phdr'] for s in self.segments}
        self.dynamic_covered = self.dynamic_idx in covered if self.is_self else True
        return self

    def describe(self):
        if self.error:
            return 'PS5-Utils: %s - %s' % (os.path.basename(self.path), self.error)
        lines = []
        lines.append('File      : %s' % self.path)
        lines.append('Container : %s' % ('%s SELF' % self.platform if self.is_self else 'bare ELF'))
        lines.append('ELF type  : 0x%04X %s' % (self.e_type, ET_SCE.get(self.e_type, '')))
        lines.append('Inner ELF : offset 0x%X' % self.inner_elf_off)
        lines.append('Segments  : %d SELF entries, %d program headers' % (len(self.segments), len(self.phdrs)))
        lines.append('DYNLIBDATA: %s' % ('present' if self.has_dynlibdata else 'absent'))
        if self.dynamic_idx is not None:
            lines.append('PT_DYNAMIC: phdr #%d, %s' % (
                self.dynamic_idx, 'data stored' if self.dynamic_covered else 'NOT stored in SELF'))
        if self.encrypted:
            lines.append('WARNING   : %d segment(s) encrypted/compressed - not fully decrypted' % self.encrypted)
        if self.is_self and not self.dynamic_covered:
            lines.append('')
            lines.append('The dynamic/import table has no stored bytes in this SELF, so the')
            lines.append('symbol-table path cannot be walked. NID renaming will use the')
            lines.append('image-wide string scan instead, which does not need it.')
        return '\n'.join(lines)


def extract_inner_elf(info, out_path):
    '''
    Carve the inner ELF out of a SELF, copying each plainly-stored segment back
    to the file offset its program header expects.

    Section headers do not survive the SELF wrapper, so their references are
    zeroed - otherwise IDA tries to read a section table that is not there.
    Returns (bytes_written, copied, skipped).
    '''
    with open(info.path, 'rb') as fh:
        d = fh.read()
    ie = info.inner_elf_off
    phdrs = info.phdrs
    end = max([p['off'] + p['filesz'] for p in phdrs if p['filesz']] or [0])
    end = max(end, 0x4000)
    buf = bytearray(end)

    ehsize = 64
    buf[0:ehsize] = d[ie:ie + ehsize]
    phoff = struct.unpack_from('<Q', d, ie + 0x20)[0]
    phentsize, phnum = struct.unpack_from('<HH', d, ie + 0x36)
    buf[phoff:phoff + phnum * phentsize] = d[ie + phoff:ie + phoff + phnum * phentsize]

    struct.pack_into('<Q', buf, 0x28, 0)   # e_shoff
    struct.pack_into('<H', buf, 0x3A, 0)   # e_shentsize
    struct.pack_into('<H', buf, 0x3C, 0)   # e_shnum
    struct.pack_into('<H', buf, 0x3E, 0)   # e_shstrndx

    copied = skipped = 0
    for s in info.segments:
        if s['enc'] or s['cmp']:
            skipped += 1
            continue
        i = s['phdr']
        if i >= len(phdrs):
            continue
        p = phdrs[i]
        if s['usz'] != p['filesz']:
            continue  # not the data segment backing this program header
        buf[p['off']:p['off'] + p['filesz']] = d[s['off']:s['off'] + p['filesz']]
        copied += 1

    with open(out_path, 'wb') as fh:
        fh.write(buf)
    return len(buf), copied, skipped


# ---------------------------------------------------------------- NID scan

def scan_nid_strings():
    '''
    Find every NID#lib#mod string in the loaded image.

    Returns a list of (ea, full_string, nid, libid, modid). Segments are read in
    chunks because a game image can be hundreds of MB and get_bytes on a whole
    segment would balloon memory.
    '''
    found = []
    CHUNK = 16 * 1024 * 1024
    OVERLAP = 64  # so a match spanning a chunk boundary is not lost
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        ea = seg.start_ea
        while ea < seg.end_ea:
            size = min(CHUNK, seg.end_ea - ea)
            buf = ida_bytes.get_bytes(ea, size)
            if not buf:
                break
            for m in NID_STRING_RE.finditer(buf):
                text = m.group().decode('ascii', 'replace')
                parts = text.split('#')
                found.append((ea + m.start(), text, parts[0], parts[1], parts[2]))
            if size < CHUNK:
                break
            ea += size - OVERLAP
    # a match can be seen twice via the chunk overlap
    seen = set()
    uniq = []
    for rec in found:
        if rec[0] in seen:
            continue
        seen.add(rec[0])
        uniq.append(rec)
    return uniq


def try_dynamic_table():
    '''
    Attempt the PT_DYNAMIC/DT_SCE_SYMTAB path against the input file.

    Returns a list of (nid, libid, modid) or [] when the table is unavailable -
    which is the case for every fake-signed dump checked, because PT_DYNAMIC has
    no stored bytes there.
    '''
    path = idaapi.get_input_file_path()
    if not path or not os.path.exists(path):
        return []
    info = SelfInfo(path).parse()
    if info.error:
        return []
    if info.is_self and not info.dynamic_covered:
        logging.info('PS5-Utils: PT_DYNAMIC not stored in this SELF - '
                     'falling back to image string scan')
        return []
    if not info.has_dynlibdata and info.is_self:
        logging.info('PS5-Utils: no PT_SCE_DYNLIBDATA - '
                     'falling back to image string scan')
        return []
    # A dump that does store the dynamic segment would be parsed here; no such
    # file has been available to validate against, so rather than ship an
    # unverified walk the scan path handles it.
    return []


def apply_rename(ea, new_name, original, stats):
    '''
    Rename one address, keeping the original identity as a comment.
    '''
    if config['comment_original'] and original:
        existing = ida_bytes.get_cmt(ea, True) or ''
        if original not in existing:
            note = ('%s\n%s' % (existing, original)).strip()
            ida_bytes.set_cmt(ea, note, True)

    if ida_name.set_name(ea, new_name, ida_name.SN_CHECK | ida_name.SN_NOWARN):
        stats['renamed'] += 1
        return True
    if config['suffix_on_collision']:
        alt = '%s_%s' % (new_name, original.split('#')[0]) if original else new_name
        alt = re.sub(r'[^A-Za-z0-9_]', '_', alt)
        if ida_name.set_name(ea, alt, ida_name.SN_CHECK | ida_name.SN_NOWARN):
            stats['renamed_suffixed'] += 1
            return True
    stats['rename_failed'] += 1
    return False


def build_extern_index():
    '''
    Map mangled import-stub names in the 'extern' segment back to their NID.

    IDA sanitizes 'bzQExy189ZI#B#C' to 'bzQExy189ZI_B_C', and prefixes a leading
    digit with '_', so the lookup key is the sanitized form rather than the NID.
    '''
    index = {}
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if ida_segment.get_segm_name(seg) != 'extern':
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            nm = ida_name.get_name(ea)
            if nm:
                index[nm] = ea
            nxt = ida_bytes.next_head(ea, seg.end_ea)
            if nxt <= ea:
                break
            ea = nxt
    return index


def mangled_variants(text):
    '''
    The sanitized spellings IDA may have given a NID import string.

    IDA replaces every character that is illegal in an identifier, so both '#'
    and the base64 '+' become '_', and a leading digit gets an '_' prefix.
    Missing the '+' case silently loses every NID containing one - about 1 in 8
    of the imports in a real title - because the extern stub is then never found.
    '''
    base = re.sub(r'[^A-Za-z0-9_]', '_', text)
    out = [base]
    if base and base[0].isdigit():
        out.append('_' + base)
    return out


def run_rename(model_unused=None):
    '''
    Resolve and apply names for every NID import in the database.
    '''
    stats = {'strings': 0, 'unique': 0, 'resolved': 0, 'unresolved': 0,
             'renamed': 0, 'renamed_suffixed': 0, 'rename_failed': 0,
             'extern_renamed': 0, 'ref_renamed': 0}

    if not catalog.names:
        n = catalog.load()
        if not n:
            ida_kernwin.warning(
                'PS5-Utils: no NID catalog loaded.\n\n'
                'Checked:\n  %s\n  %s\n\n'
                'Set repo_path in %s, or use "Clone / update ps5rs".'
                % (repo_file(config['nids_csv']), repo_file(config['stubs_txt']), CONFIG_NAME))
            return

    ida_kernwin.show_wait_box('PS5-Utils: scanning for NID imports...')
    try:
        # try the structured path first; it returns [] on fake-signed dumps
        try_dynamic_table()

        hits = scan_nid_strings()
        stats['strings'] = len(hits)
        uniq = {h[2] for h in hits}
        stats['unique'] = len(uniq)

        extern_index = build_extern_index() if config['rename_extern'] else {}
        unresolved = []

        for i, (ea, text, nid, libid, modid) in enumerate(hits):
            if i % 256 == 0:
                if ida_kernwin.user_cancelled():
                    logging.warning('PS5-Utils: cancelled')
                    break
                ida_kernwin.replace_wait_box(
                    'PS5-Utils: %d/%d imports' % (i, len(hits)))

            name = catalog.resolve(nid)
            if not name:
                stats['unresolved'] += 1
                unresolved.append((nid, text, ea))
                continue
            stats['resolved'] += 1

            final = config['name_template'].format(
                name=name, nid=nid, lib=libid, mod=modid)
            final = re.sub(r'[^A-Za-z0-9_]', '_', final)

            # the extern stub is what call sites actually reference, so it is
            # the rename that makes the disassembly readable
            if config['rename_extern']:
                for variant in mangled_variants(text):
                    tgt = extern_index.get(variant)
                    if tgt is not None:
                        if apply_rename(tgt, final, text, stats):
                            stats['extern_renamed'] += 1
                        break

            if config['rename_string_refs']:
                for xref in idautils.XrefsTo(ea):
                    if apply_rename(xref.frm, '%s_ptr' % final, text, stats):
                        stats['ref_renamed'] += 1
                    break

        write_unresolved(unresolved)
    finally:
        ida_kernwin.hide_wait_box()

    pct = 100.0 * stats['resolved'] / max(1, stats['strings'])
    summary = (
        'NID strings found : %d\n'
        'Unique NIDs       : %d\n'
        'Resolved          : %d (%.1f%%)\n'
        'Unresolved        : %d\n\n'
        'extern stubs renamed : %d\n'
        'pointers renamed     : %d\n'
        'collisions suffixed  : %d\n'
        'rename failures      : %d'
        % (stats['strings'], stats['unique'], stats['resolved'], pct,
           stats['unresolved'], stats['extern_renamed'], stats['ref_renamed'],
           stats['renamed_suffixed'], stats['rename_failed']))
    print('=' * 60)
    print('PS5-Utils: import rename complete')
    print('=' * 60)
    print(summary)
    ida_kernwin.info('PS5-Utils\n\n' + summary)


def report_path(filename):
    '''
    Reports land next to the analyzed binary, in a subfolder.
    '''
    src = idaapi.get_input_file_path() or ''
    base = os.path.dirname(src) or os.getcwd()
    d = config['report_dir']
    out = d if os.path.isabs(d) else os.path.join(base, d)
    try:
        os.makedirs(out, exist_ok=True)
    except OSError as e:
        logging.error('PS5-Utils: cannot create %s - %s', out, e)
        return None
    return os.path.join(out, filename)


def write_unresolved(unresolved):
    '''
    Dump unnamed NIDs in the column order merge_nids.py appends, so discoveries
    can be fed straight back into nids.csv.
    '''
    if not unresolved:
        return
    path = report_path(config['unresolved_csv'])
    if not path:
        return
    try:
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            w.writerow(['nid', 'nid_hex', 'name', 'library', 'derived', 'sources'])
            for nid, text, ea in sorted(set((u[0], u[1], u[2]) for u in unresolved)):
                val = nid_to_u64(nid)
                w.writerow([nid, '0x%016X' % val if val is not None else '',
                            '', '', '0', 'ida:%s' % os.path.basename(
                                idaapi.get_input_file_path() or 'unknown')])
        logging.info('PS5-Utils: wrote %d unresolved NIDs to %s', len(unresolved), path)
    except OSError as e:
        logging.error('PS5-Utils: cannot write %s - %s', path, e)


def run_detect():
    '''
    Identify the container/platform of the analyzed file.
    '''
    path = idaapi.get_input_file_path()
    if not path:
        ida_kernwin.warning('PS5-Utils: no input file path for this database.')
        return
    if not os.path.exists(path):
        ida_kernwin.warning('PS5-Utils: input file not found on disk:\n%s' % path)
        return
    info = SelfInfo(path).parse()
    text = info.describe()
    print('=' * 60)
    print(text)
    print('=' * 60)
    ida_kernwin.info(text)


def run_extract():
    '''
    Carve the inner ELF out of the analyzed SELF.
    '''
    path = idaapi.get_input_file_path()
    if not path or not os.path.exists(path):
        ida_kernwin.warning('PS5-Utils: input file not available on disk.')
        return
    info = SelfInfo(path).parse()
    if info.error:
        ida_kernwin.warning('PS5-Utils: %s' % info.error)
        return
    if not info.is_self:
        ida_kernwin.info('PS5-Utils: this file is already a bare ELF - nothing to extract.')
        return

    out = os.path.splitext(path)[0] + '_extracted.elf'
    if os.path.exists(out):
        if ida_kernwin.ask_yn(0, 'Overwrite existing file?\n\n%s' % out) != ida_kernwin.ASKBTN_YES:
            return
    try:
        size, copied, skipped = extract_inner_elf(info, out)
    except (OSError, struct.error) as e:
        ida_kernwin.warning('PS5-Utils: extraction failed - %s' % e)
        return

    msg = ('Wrote %s\n\n%d bytes\nSegments copied: %d\nSegments skipped: %d'
           % (out, size, copied, skipped))
    if skipped:
        msg += ('\n\nSkipped segments are encrypted/compressed; this SELF is not '
                'fully decrypted and the extracted ELF will be incomplete.')
    print(msg)
    ida_kernwin.info('PS5-Utils\n\n' + msg)


def run_deps():
    '''
    Report the module/library names the binary references.
    '''
    path = idaapi.get_input_file_path()
    names = set()
    if path and os.path.exists(path):
        try:
            with open(path, 'rb') as fh:
                blob = fh.read()
            for m in re.finditer(rb'(lib[A-Za-z0-9_]{2,60}(?:\.s?prx)?)\x00', blob):
                names.add(m.group(1).decode('ascii', 'replace'))
        except OSError:
            pass

    if not catalog.names:
        catalog.load()
    libs = {}
    for ea, text, nid, libid, modid in scan_nid_strings():
        lib = catalog.library.get(nid)
        if lib:
            libs[lib] = libs.get(lib, 0) + 1

    lines = ['Modules referenced in the binary image:']
    for n in sorted(names):
        lines.append('  %s' % n)
    lines.append('')
    lines.append('Imports by attributed library:')
    for lib, cnt in sorted(libs.items(), key=lambda kv: -kv[1]):
        lines.append('  %-44s %d' % (lib, cnt))
    text = '\n'.join(lines)

    out = report_path(config['deps_report'])
    if out:
        try:
            with open(out, 'w', encoding='utf-8') as fh:
                fh.write(text + '\n')
            text += '\n\nWritten to %s' % out
        except OSError as e:
            logging.error('PS5-Utils: cannot write deps report - %s', e)
    print(text)
    ida_kernwin.info('PS5-Utils\n\n' + text[:3000])


def run_repo_update():
    '''
    Clone ps5rs if absent, otherwise pull. Never runs automatically - updates
    happen only from this menu action.
    '''
    repo = repo_root()
    url = config['repo_url']

    def worker():
        try:
            if not os.path.isdir(os.path.join(repo, '.git')):
                if os.path.exists(repo) and os.listdir(repo):
                    msg = ('PS5-Utils: %s exists but is not a git checkout.\n'
                           'Move it aside or point repo_path elsewhere.' % repo)
                    logging.error(msg)
                    ida_kernwin.execute_sync(partial(ida_kernwin.warning, msg),
                                             ida_kernwin.MFF_FAST)
                    return
                logging.info('PS5-Utils: cloning %s -> %s', url, repo)
                r = subprocess.run(['git', 'clone', url, repo],
                                   capture_output=True, text=True, timeout=1800)
                action = 'clone'
            else:
                logging.info('PS5-Utils: pulling %s', repo)
                r = subprocess.run(['git', '-C', repo, 'pull', '--ff-only'],
                                   capture_output=True, text=True, timeout=600)
                action = 'pull'
            out = (r.stdout or '') + (r.stderr or '')
            ok = r.returncode == 0
            msg = 'PS5-Utils: git %s %s\n\n%s' % (
                action, 'succeeded' if ok else 'FAILED', out.strip()[:1500])
            logging.info(msg)
            if ok:
                catalog.__init__()
                catalog.load()
                msg += '\n\nCatalog reloaded: %d NIDs' % len(catalog.names)
            ida_kernwin.execute_sync(partial(ida_kernwin.info, msg), ida_kernwin.MFF_FAST)
        except FileNotFoundError:
            ida_kernwin.execute_sync(
                partial(ida_kernwin.warning,
                        'PS5-Utils: git not found on PATH.'), ida_kernwin.MFF_FAST)
        except subprocess.TimeoutExpired:
            ida_kernwin.execute_sync(
                partial(ida_kernwin.warning,
                        'PS5-Utils: git timed out.'), ida_kernwin.MFF_FAST)

    threading.Thread(target=worker).start()


# ---------------------------------------------------------------- actions

class PS5Action(ida_kernwin.action_handler_t):
    def __init__(self, fn):
        self.fn = fn
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            self.fn()
        except Exception as e:
            logging.exception('PS5-Utils: action failed')
            ida_kernwin.warning('PS5-Utils: %s' % e)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ('ps5utils:detect',  'Detect platform (PS4/PS5/ELF)', run_detect),
    ('ps5utils:rename',  'Rename NID imports',            run_rename),
    ('ps5utils:extract', 'Extract inner ELF to disk',     run_extract),
    ('ps5utils:deps',    'Module dependency report',      run_deps),
    ('ps5utils:update',  'Clone / update ps5rs',          run_repo_update),
]

for aid, label, fn in ACTIONS:
    ida_kernwin.register_action(ida_kernwin.action_desc_t(
        aid, label, PS5Action(fn), None, label, 199))


class PS5Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wt = ida_kernwin.get_widget_type(widget)
        if wt in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            for aid, label, fn in ACTIONS:
                ida_kernwin.attach_action_to_popup(widget, popup, aid, 'PS5-Utils/')


hooks = PS5Hooks()
hooks.hook()

print('PS5-Utils loaded - right-click menu "PS5-Utils" (repo: %s)' % repo_root())


def unload_plugin():
    global hooks
    for aid, label, fn in ACTIONS:
        ida_kernwin.unregister_action(aid)
    if hooks is not None:
        hooks.unhook()
        hooks = None
    print('PS5-Utils unloaded')
