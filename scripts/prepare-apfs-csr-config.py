#!/usr/bin/env python3
"""Select XNU's real DT-backed CSR policy in an isolated master-config copy."""
import argparse
from pathlib import Path
import shutil


def prepare(source, output):
    machine = 'MASTER.arm64.bcm2837'
    text = (source / machine).read_text()
    old = '#  SECURITY_BASE =    [ config_macf kernel_integrity config_secure_bsd_root reslide_shared_cache ]'
    if text.count(old) != 1:
        raise ValueError('Unexpected BCM2837 security configuration')
    output.mkdir(parents=True, exist_ok=True)
    for path in source.glob('MASTER*'):
        if path.is_file():
            shutil.copyfile(path, output / path.name)
    (output / machine).write_text(text.replace(old, old.replace(
        'config_macf ', 'config_macf config_csr config_csr_from_dt ')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.source, args.output)
