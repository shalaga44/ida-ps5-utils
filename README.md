# PS5-Utils

An IDA Pro plugin for PS4/PS5 binaries. Renames NID-mangled imports to real
function names, detects SELF containers, extracts the inner ELF, and reports
module dependencies.

Uses the NID catalog from [ps5rs](https://github.com/claimore22/ps5rs)
(~175,000 hash-to-name mappings).

```
extern:8059FC988  bzQExy189ZI_B_C        ->  _init_env
extern:8059FC9B0  pO96TwzOm5E_A_B        ->  sceKernelGetDirectMemorySize
extern:8059FC9F8  j4ViWNHEgww_B_C        ->  strlen
```

## Why

A PS5 executable imports functions by NID — an 11-character hash of the symbol
name — so IDA shows `bzQExy189ZI#B#C` instead of `_init_env`. Every call into a
system library is unreadable until those hashes are resolved.

## Install

```sh
git clone https://github.com/<you>/ps5utils ~/.idapro/plugins/ps5utils
```

Then run **Clone / update ps5rs** from the menu to fetch the NID catalog. By
default it clones into a temp directory, so there is nothing to configure. If
you already have a ps5rs checkout, point `repo_path` at it instead.

Requires IDA 9.x with Python 3. No third-party Python packages.

## Use

Right-click in the disassembly or pseudocode view → **PS5-Utils**:

| Action | What it does |
|---|---|
| Detect platform (PS4/PS5/ELF) | Identifies the container, ELF type, and whether the dynamic table is readable |
| Rename NID imports | Resolves every NID in the image and renames the import stubs |
| Extract inner ELF to disk | Carves the ELF out of a SELF wrapper, writes `<name>_extracted.elf` |
| Module dependency report | Lists referenced modules and imports per library |
| Clone / update ps5rs | Clones the catalog repo, or pulls if already present |

Updates never run automatically — only when you pick that action.

Start with **Detect platform**; it is read-only. **Rename NID imports** modifies
the database, so save first if you want a rollback point.

## How it resolves imports

The plugin scans the loaded image for `NID#lib#mod` strings, resolves each NID
against the catalog, and renames the matching stub in IDA's `extern` segment —
the slot that call sites actually reference.

It attempts the `PT_DYNAMIC` / `DT_SCE_SYMTAB` symbol-table path first, but on
every fake-signed dump tested, the SELF segment table has no entry backing
`PT_DYNAMIC`, so those bytes were never stored and the table cannot be walked.
The string scan does not depend on it and works on flat binary loads.

Measured on a real title (93,678 functions):

| | |
|---|---|
| NID strings found | 1,301 |
| Resolved against catalog | 1,299 (99.8%) |
| Import stubs in `extern` | 1,297 |

Unresolved NIDs are written to `unresolved_nids.csv` in the column order
[`merge_nids.py`](https://github.com/claimore22/ps5rs/blob/master/merge_nids.py)
expects, so discoveries can be appended to `nids.csv` directly.

## Configuration

`ps5utils_config.json`, next to the plugin. Keys starting with `_` are comments.
Delete the file to fall back to built-in defaults; a malformed file logs an error
and uses defaults rather than failing to load.

```json
{
    "repo_path": "",
    "repo_url": "git@github.com:claimore22/ps5rs.git",
    "nids_csv": "data/nids.csv",
    "stubs_txt": "data/stubs.txt",
    "name_template": "{name}",
    "suffix_on_collision": true,
    "rename_extern": true,
    "rename_string_refs": true,
    "comment_original": true,
    "accept_sources": [],
    "report_dir": "ps5utils_reports",
    "unresolved_csv": "unresolved_nids.csv",
    "deps_report": "module_deps.txt"
}
```

- `repo_path` — empty clones into a temp directory. Set a path to keep the
  checkout permanently, or to reuse one you already have.
- `name_template` — fields are `{name}`, `{nid}`, `{lib}`, `{mod}`. Use
  `"{name}_{nid}"` to keep the hash visible in every name.
- `accept_sources` — restrict to catalog sources you trust, e.g.
  `["aerolib", "ps5rs"]`. Empty accepts any.
- `comment_original` — records the original NID as a repeatable comment, so the
  pre-rename identity survives in the database.
- `suffix_on_collision` — IDA names must be unique; when one is taken, append
  `_<nid>` rather than skipping the rename.
- `report_dir` — where `unresolved_csv` and `deps_report` are written. A relative
  path lands next to the analyzed binary.

## Notes

- Works on SELF files loaded as flat binaries and on already-extracted ELFs.
- Extraction only handles plainly-stored segments. Encrypted or compressed
  segments are skipped with a warning — decrypting them needs console keys.
- The two PS5 base64 characters are `+` and `-`, not `+/`. A standard base64
  decoder silently produces wrong NID values.

## Credits

NID catalog and data files from [ps5rs](https://github.com/claimore22/ps5rs) by
claimore22, which sources its NID database from SharpEmu's community catalog.

## License

GPL-2.0-only.
