pkg-extract
===========

A command-line extractor for PlayStation 4 `.pkg` files, written in Rust.
Based on the [shadPS4 pkg extractor](https://github.com/AzaharPlus/shadPS4Plus).

Usage
-----

```sh
# Extract into the current directory. Creates <TITLE_ID>/ (or
# <TITLE_ID>/<ENTITLEMENT>/ for DLC) and populates it with sce_sys/ metadata
# plus the PFS filesystem (eboot.bin, dvdroot_ps4/*, etc).
pkg-extract some-game.pkg

# Extract into /somewhere/else instead.
pkg-extract -o /somewhere/else some-game.pkg

# List the pkg contents without extracting (-v for ls -l style details).
pkg-extract -l some-game.pkg
pkg-extract -lv some-game.pkg

# Print the pkg's title id and type (base game / patch / DLC) and exit.
pkg-extract --info some-game.pkg

# Just exit with 101 (base game), 102 (patch), or 103 (DLC).
pkg-extract --check-type some-game.pkg
```

Build with `cargo build --release`.

License
-------

Copyright © 2026 David Caldwell <david_pkgextract@porkrind.org>

*TLDR: [GPLv3](LICENSE.md). You can redistribute the .exe (or a modified
version) as long as you ship the source code used to build it alongside.*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
