# Private test artifacts

These archives are private. The database contains third-party intelligence with unverified redistribution rights; keep it within the authorized private environment.

On Linux x86_64, from this directory, verify and extract into owner-only directories:

```sh
sha256sum -c SHA256SUMS
umask 077
mkdir -p "$HOME/raxosentinel-test/bin-package" "$HOME/raxosentinel-test/private"
chmod 700 "$HOME/raxosentinel-test" "$HOME/raxosentinel-test/bin-package" "$HOME/raxosentinel-test/private"
tar -xzf binary/raxosentinel-38a6a14-linux-x86_64.tar.gz -C "$HOME/raxosentinel-test/bin-package"
tar -xzf database/raxosentinel-private-phase2d6-unified.tar.gz -C "$HOME/raxosentinel-test/private"
"$HOME/raxosentinel-test/bin-package/bin/raxosentinel" db sources --root "$HOME/raxosentinel-test/private" --generation phase2d6-unified
```

The database generation contains 542,057 indicators. The executable was built from commit `38a6a14da123687943a665e410f630c776e9b729` for `x86_64-unknown-linux-gnu`. The binary archive also contains staging installation instructions; do not run the installer without reviewing the target environment.
