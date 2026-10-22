#!/usr/bin/env python3
"""Measure what an arm64e kernelcache needs from a CPU without pointer authentication.

Reads a decompressed MH_FILESET kernelcache (unixnu ipsw fetch KernelCache) and classifies every
instruction word of every __TEXT_EXEC,__text section by its Arm ARM encoding:

  hint     PAC/AUT/XPACLRI and BTI in the HINT space: NOPs on a core without FEAT_PAuth/FEAT_BTI
  nonhint  RETA*, ERETA*, BRA*/BLRA*, LDRA*, PAC*/AUT*/XPAC* with registers, PACGA: undefined there
  flagm    CFINV, RMIF, SETF8/16 (FEAT_FlagM), AXFLAG/XAFLAG (FEAT_FlagM2)
  lrcpc2   LDAPUR*/STLUR* (FEAT_LRCPC2)
  gxf      Apple GENTER/GEXIT (guarded execution, the SPTM/PPL transitions)

The counts are per fileset entry (the kernel and each kext) and in total, as text or --json. Words in
__text are taken as instructions; the rare data islands in kernel text can add a few false matches.
"""
import argparse
import json
import struct
from collections import Counter
from pathlib import Path

import numpy

LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035

# (class, name, mask, value), Arm Architecture Reference Manual encodings.
PATTERNS = [
    # HINT #imm is 0xd503201f | CRm << 8 | op2 << 5; CRm 3 holds the SP and Z forms, CRm 1 the 1716 forms.
    ('hint', 'PACIAZ/PACIASP/PACIBZ/PACIBSP/AUTIAZ/AUTIASP/AUTIBZ/AUTIBSP', 0xffffff1f, 0xd503231f),
    ('hint', 'PACIA1716/PACIB1716/AUTIA1716/AUTIB1716', 0xffffff5f, 0xd503211f),
    ('hint', 'XPACLRI', 0xffffffff, 0xd50320ff),
    ('hint', 'BTI', 0xffffff3f, 0xd503241f),
    ('nonhint', 'RETAA/RETAB', 0xfffffbff, 0xd65f0bff),
    ('nonhint', 'ERETAA/ERETAB', 0xfffffbff, 0xd69f0bff),
    ('nonhint', 'BRAAZ/BRABZ', 0xfffff81f, 0xd61f081f),
    ('nonhint', 'BLRAAZ/BLRABZ', 0xfffff81f, 0xd63f081f),
    ('nonhint', 'BRAA/BRAB', 0xfffff800, 0xd71f0800),
    ('nonhint', 'BLRAA/BLRAB', 0xfffff800, 0xd73f0800),
    ('nonhint', 'LDRAA/LDRAB', 0xff200400, 0xf8200400),
    ('nonhint', 'XPACI/XPACD', 0xfffffbe0, 0xdac143e0),
    ('nonhint', 'PAC*/AUT* (register)', 0xffffc000, 0xdac10000),
    ('nonhint', 'PACGA', 0xffe0fc00, 0x9ac03000),
    ('flagm', 'CFINV', 0xffffffff, 0xd500401f),
    ('flagm', 'RMIF', 0xffe07c10, 0xba000400),
    ('flagm', 'SETF8/SETF16', 0xffffbc1f, 0x3a00080d),
    ('flagm', 'AXFLAG', 0xffffffff, 0xd500405f),
    ('flagm', 'XAFLAG', 0xffffffff, 0xd500403f),
    ('lrcpc2', 'LDAPUR*/STLUR*', 0x3f200c00, 0x19000000),
    ('gxf', 'GEXIT (0x00201400)/GENTER (0x00201420)', 0xffffffc0, 0x00201400),
]


def segments(data, header):
    magic, _, _, _, count, size = struct.unpack_from('<6I', data, header)
    if magic != 0xfeedfacf:
        raise SystemExit(f'no 64-bit Mach-O header at {header:#x}')
    offset, result, entries = header + 32, [], []
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        if command == LC_SEGMENT_64:
            name = data[offset + 8:offset + 24].rstrip(b'\0').decode()
            nsects = struct.unpack_from('<I', data, offset + 64)[0]
            for index in range(nsects):
                at = offset + 72 + 80 * index
                sect = data[at:at + 16].rstrip(b'\0').decode()
                _, size_, fileoff = struct.unpack_from('<QQI', data, at + 32)
                result.append((name, sect, fileoff, size_))
        elif command == LC_FILESET_ENTRY:
            _, fileoff, name_offset = struct.unpack_from('<QQI', data, offset + 8)
            entries.append((data[offset + name_offset:data.index(b'\0', offset + name_offset)].decode(), fileoff))
        offset += length
    return result, entries


def classify(blob):
    """Count each pattern; a word counts for the first pattern it matches, as in the table order."""
    words = numpy.frombuffer(blob, dtype='<u4')
    taken = numpy.zeros(len(words), dtype=bool)
    counts = Counter()
    for kind, name, mask, value in PATTERNS:
        hit = ((words & numpy.uint32(mask)) == numpy.uint32(value)) & ~taken
        taken |= hit
        if hit.any():
            counts[(kind, name)] += int(hit.sum())
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('kernelcache', type=Path)
    parser.add_argument('--json', type=Path, help='also write the counts here')
    parser.add_argument('--top', type=int, default=25, help='entries to list, by undefined-instruction count')
    args = parser.parse_args()
    data = args.kernelcache.read_bytes()
    cpu, subtype, filetype = struct.unpack_from('<III', data, 4)
    if (cpu, subtype & 0xffffff, filetype) != (0x100000c, 2, 12):
        raise SystemExit('expected an arm64e MH_FILESET kernelcache')
    _, entries = segments(data, 0)
    report = {}
    total = Counter()
    for name, header in entries:
        sections, _ = segments(data, header)
        counts = Counter()
        size = 0
        for segment, section, fileoff, length in sections:
            if segment == '__TEXT_EXEC' and section == '__text':
                blob = data[fileoff:fileoff + length - length % 4]
                counts += classify(blob)
                size += len(blob) // 4
        total += counts
        report[name] = {'instructions': size, **{f'{kind}:{label}': value for (kind, label), value in counts.items()}}
    by_kind = Counter()
    for (kind, _), value in total.items():
        by_kind[kind] += value
    words = sum(entry['instructions'] for entry in report.values())
    print(f'{len(entries)} fileset entries, {words} __text words')
    for kind in ('hint', 'nonhint', 'flagm', 'lrcpc2', 'gxf'):
        print(f'  {kind:8s} {by_kind[kind]:9d}')
        for (k, label), value in sorted(total.items(), key=lambda item: -item[1]):
            if k == kind:
                print(f'           {value:9d}  {label}')
    undefined = lambda entry: sum(v for k, v in entry.items() if k.split(':')[0] in ('nonhint', 'flagm', 'lrcpc2', 'gxf'))
    print(f'entries by undefined instructions (top {args.top}):')
    for name, entry in sorted(report.items(), key=lambda item: -undefined(item[1]))[:args.top]:
        print(f'  {undefined(entry):8d} / {entry["instructions"]:8d}  {name}')
    clean = [name for name, entry in report.items() if entry['instructions'] and undefined(entry) == 0]
    print(f'entries with no undefined instruction: {len(clean)}')
    if args.json:
        args.json.write_text(json.dumps({'total': {f'{k}:{l}': v for (k, l), v in total.items()}, 'entries': report}, indent=1))


if __name__ == '__main__':
    main()
