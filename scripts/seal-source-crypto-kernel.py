#!/usr/bin/env python3
"""Fill the source provider's normal POST HMAC field after final kernel link.

Implements the source fipspost_get_hmac/hmacfiletool build contract: HMAC-SHA256
with a one-byte zero key over the first __TEXT[ _EXEC ]/__text section.
No selftest or integrity check is disabled. Only locally compiled input is used.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('kernel', type=Path)
parser.add_argument('--static-if-defaults', action='store_true',
                    help='XNU 12377: seal for its audited default static-if startup patches; requires default validation_disables/serverperfmode/lcks')
args = parser.parse_args()
data = bytearray(args.kernel.read_bytes())
if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
    raise SystemExit('Expected a source-built ordinary ARM64 MH_EXECUTE kernel')
if b'_source_corecrypto14_bootstrap\0' not in data:
    raise SystemExit('Input does not contain the explicit source-provider bootstrap')
offset = 32
code = None
integrity = None
segments = []
sections = {}
symbols = {}
for _ in range(struct.unpack_from('<I', data, 16)[0]):
    cmd, length = struct.unpack_from('<II', data, offset)
    if cmd == 0x19:
        name, va, _, fileoff, _ = struct.unpack_from('<16s4Q', data, offset + 8)
        name = name.rstrip(b'\0')
        segments.append((name, va, fileoff))
        for index in range(struct.unpack_from('<I', data, offset + 64)[0]):
            section = offset + 72 + index * 80
            section_name, segment_name, address, size, position = struct.unpack_from('<16s16sQQI', data, section)
            sections[(segment_name.rstrip(b'\0'), section_name.rstrip(b'\0'))] = (address, size, position)
            if section_name.rstrip(b'\0') == b'__text' and segment_name.rstrip(b'\0') in (b'__TEXT', b'__TEXT_EXEC') and code is None:
                code = (position, size, address)
            if section_name.rstrip(b'\0') == b'__fips_hmacs':
                if integrity is not None or size != 32:
                    raise SystemExit('Expected exactly one 32-byte POST HMAC field')
                integrity = position
    elif cmd == 2:
        symoff, count, stroff, strsize = struct.unpack_from('<4I', data, offset + 8)
        strings = data[stroff:stroff + strsize]
        for index in range(count):
            name, kind, section, _, value = struct.unpack_from('<IBBHQ', data, symoff + index*16)
            end = strings.find(0, name) if name < strsize else -1
            if end >= 0 and kind & 0xEE == 0x0E and section:
                symbols.setdefault(bytes(strings[name:end]).decode(), []).append(value)
    offset += length
if code is None or integrity is None:
    raise SystemExit('Missing real provider code or POST HMAC field')
base = next(va for name, va, _ in segments if name == b'__TEXT')
if code[2] - base != code[0]:
    raise SystemExit('Runtime header-relative text mapping differs from the POST file-offset contract')
if code[0] <= integrity < code[0] + code[1]:
    raise SystemExit('HMAC field must be outside the hashed instructions')
expected_code = bytearray(data[code[0]:code[0] + code[1]])
runtime_patches = []
if args.static_if_defaults:
    def symbol(name):
        values = symbols.get(name, [])
        if len(values) != 1:
            raise SystemExit(f'Require one {name} symbol for audited static-if profile')
        return values[0]

    def file_offset(va, length):
        for address, size, position in sections.values():
            if address <= va and va + length <= address + size:
                return position + va - address
        raise SystemExit('Static-if address is not in a file-backed section')

    abi = struct.unpack_from('<I', data, file_offset(symbol('_static_if_abi'), 4))[0]
    if abi != 1:
        raise SystemExit('Unsupported static-if ABI')
    init = sections.get((b'__BOOTDATA', b'__static_ifinit'))
    entries = sections.get((b'__BOOTDATA', b'__static_if'))
    if init is None or init[1] != 16 or entries is None or entries[1] % 16:
        raise SystemExit('Unexpected static-if initializer/table layout')
    initializers = struct.unpack_from('<2Q', data, init[2])
    if set(initializers) != {symbol('_kern_feature_override_apply'), symbol('_static_if_tests_setup')}:
        raise SystemExit('Unaudited static-if initializer: cannot predict POST code image')
    keys = {symbol('_static_if_test_key_true_to_false_jump_key'): True,
            symbol('_static_if_test_key_false_to_true_jump_key'): False}
    counts = {key: 0 for key in keys}
    for key, initially_enabled in keys.items():
        count, initial, modified = struct.unpack_from('<hBB', data, file_offset(key, 4))
        if (count, initial, modified) != (0 if initially_enabled else -1, int(initially_enabled), 0):
            raise SystemExit('Unexpected initial static-if test key')
    for offset in range(entries[2], entries[2] + entries[1], 16):
        relative, target, link = struct.unpack_from('<iiQ', data, offset)
        key = link & ~3
        if key not in keys:
            continue
        patch_va = entries[0] + offset - entries[2] + relative
        within = patch_va - code[2]
        if not 0 <= within <= code[1] - 4 or target % 4 or not -(1 << 27) <= target < (1 << 27):
            raise SystemExit('Invalid static-if patch point or branch')
        branch = 0x14000000 | ((target // 4) & 0x3ffffff)
        nop = 0xd503201f
        old = struct.unpack_from('<I', expected_code, within)[0]
        initial_instruction = branch if link & 1 else nop
        if old != initial_instruction:
            raise SystemExit('Static-if instruction differs from its initial table metadata')
        final_instruction = nop if link & 1 else branch
        struct.pack_into('<I', expected_code, within, final_instruction)
        runtime_patches.append({'va': hex(patch_va), 'file_instruction': hex(old),
                                'post_startup_instruction': hex(final_instruction)})
        counts[key] += 1
    if not all(0 < count <= 16 for count in counts.values()):
        raise SystemExit('Unexpected static-if test patch count')
mac = hmac.digest(b'\0', expected_code, 'sha256')
data[integrity:integrity + 32] = mac
args.kernel.write_bytes(data)
report = {'kernel_sha256': hashlib.sha256(data).hexdigest(), 'code_file_offset': hex(code[0]),
          'code_bytes': code[1], 'hmac_file_offset': hex(integrity), 'hmac_sha256': mac.hex(),
          'static_if_default_profile': args.static_if_defaults,
          'expected_runtime_instruction_changes': runtime_patches,
          'runtime_selftests_executed': False}
args.kernel.with_suffix(args.kernel.suffix + '.crypto-hmac.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Source kernel POST integrity field populated ({len(runtime_patches)} expected startup instruction changes); runtime selftests are still required')
