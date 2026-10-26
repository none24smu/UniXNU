"""Apply an ordered patch series only to the base or an exact recorded prefix.

A private Git index computes each expected tree without changing the source's
index. This also covers overlapping patches and newly added source files.
"""
import os
from pathlib import Path
import subprocess
import tempfile


def apply_series(source, patches):
    source = Path(source)
    patches = [Path(p).resolve() for p in patches]

    def git(*args, env=None):
        try:
            return subprocess.check_output(
                ['git', '-C', str(source), *args], env=env, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            raise ValueError('Recorded source check failed: ' + ' '.join(args) + '\n' +
                             error.stderr.decode(errors='replace')) from error

    with tempfile.TemporaryDirectory(prefix='recorded-patches-') as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
        git('read-tree', 'HEAD', env=env)

        def tree():
            return dict((entry.split(b'\t', 1)[1].decode(), entry.split()[1].decode())
                        for entry in git('ls-files', '--stage', '-z', env=env).split(b'\0') if entry)

        states = [tree()]
        for patch in patches:
            git('apply', '--cached', str(patch), env=env)
            states.append(tree())
        touched = {name for state in states for name in state
                   if any(state.get(name) != other.get(name) for other in states)}
        changed = set(git('diff', '--name-only', 'HEAD', '--').decode().splitlines())
        untracked = set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
        if (changed | untracked) - touched:
            raise ValueError('Translator contains changes outside its recorded patches')
        actual = {}
        for name in touched:
            path = source / name
            actual[name] = git('hash-object', '--no-filters', '--', name).decode().strip() if path.exists() else None
        prefixes = [i for i, state in enumerate(states)
                    if all(actual[name] == state.get(name) for name in touched)]
        if not prefixes:
            raise ValueError('Translator differs from the base plus a recorded patch prefix')
        for patch in patches[max(prefixes):]:
            git('apply', str(patch))
        for name in touched:
            path = source / name
            value = git('hash-object', '--no-filters', '--', name).decode().strip() if path.exists() else None
            if value != states[-1].get(name):
                raise ValueError('Translator patch result differs from the recorded source: ' + name)
