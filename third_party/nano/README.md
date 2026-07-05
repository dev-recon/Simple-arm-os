GNU nano for ArmOS
==================

ArmOS does not vendor GNU nano sources in the repository.  The port is built by
`tools/build_nano.sh`, which downloads the selected upstream release into
`build/nano/download`, configures a tiny static build, and installs the runtime
bundle under:

```text
userfs/opt/nano/
```

The first supported profile is intentionally conservative:

- `--enable-tiny`
- `--disable-nls`
- `--disable-utf8`
- no syntax/color/speller/browser extras yet
- static link against the ArmOS newlib port and `/opt/ncurses/lib/libncurses.a`

Build from the repository root:

```sh
BUILD_NCURSES=1 BUILD_NANO=1 ./build.sh
```

The installed editor is available as:

```text
/opt/nano/bin/nano
```

The default mash startup files add `/opt/nano/bin` to `PATH`.
