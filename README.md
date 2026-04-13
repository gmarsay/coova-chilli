CoovaChilli is a feature rich software access controller that provides a
captive portal / walled-garden environment and uses RADIUS or a HTTP protocol
for access provisioning and accounting.
Released under the GNU General Public License (GPL).

Visit website for documentation and archived content

[https://coova.github.io/](https://coova.github.io/)

Please use the [Github issues](https://github.com/coova/coova-chilli/issues) section for bug reports only.

To get started after cloning the repository (Meson + Ninja):

  `meson setup build`

  `meson compile -C build`

  `meson install -C build`

Dependencies: a C99 compiler, **pkg-config**, **libbstring** (`bstring.pc`, e.g. [msteinert/bstring](https://github.com/msteinert/bstring)), **libjson-c**, **gengetopt**, **patch**; optional **OpenSSL** (default: on, `-Dopenssl=false` to disable); **libbsd** if the C library has no `strlcpy`.

Example with bstring installed under `/usr/local`:

  `PKG_CONFIG_PATH=/usr/local/lib/pkgconfig meson setup build`

[![Github Actions Build Status](https://github.com/coova/coova-chilli/actions/workflows/actions.yml/badge.svg)](https://github.com/coova/coova-chilli/actions/workflows/actions.yml)
