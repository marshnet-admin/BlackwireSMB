# Reader upgrades and the predecessor safeguard

Each installed game keeps its own copy of the in-game reader,
`fakelib2/libSceAmpr.sprx`. When a newer `Blackwire.elf` embeds a different
reader, the resident swaps it inside each game folder the next time that game
is played or set up. Game files are kept and nothing is sent again.

The swap only happens when the reader already in the game folder is
recognized **by its exact size and SHA-256**. Recognized readers are compiled
into `pu_previous_match()` in
[`src/blackwire/library/preload_bundle.c`](../src/blackwire/library/preload_bundle.c).
An unrecognized reader is refused with `reader_upgrade_predecessor_unknown`,
and the only fix is uninstalling and reinstalling that game. The same list
also authorizes Uninstall to remove an older reader.

## Rule: pin the old reader before shipping a new one

Any change that alters the reader bytes (anything under `src/blackwire/reader/`,
`src/blackwire/streamreader/` used by the reader, or `tools/build/reader*.py`)
must, in the same commit:

1. Take the reader the console games currently have. `GET /health` on the
   running resident (`http://<PS5>:5918/health`) reports it as `readerSha256`;
   the matching file is `build/<build-name>/reader/libSceAmpr.sprx`.
2. Add a `static const struct pb_pin` with that exact size and SHA-256 and
   list it in `known[]` in `pu_previous_match()`.
3. Add positive and negative checks for it in
   `tests/dashboard/lifecycle/test_preload_bundle_upgrade.c` (exact size
   matches; size ±1 and a flipped hash byte do not).
4. Keep a copy of the old reader in `build/backups/readers/` (ignored by git).
5. Add a row to the table below.

Changes that only touch the resident or dashboard do not change the reader
and need no pin. To check, compare the new build's
`build/<name>/reader/libSceAmpr.sprx` SHA-256 with the current `readerSha256`.

After loading a build with a new reader, keep games closed while it loads,
then press Play on each game once; the first launch performs the swap.

## Pinned fork readers

| Pin | Size (bytes) | SHA-256 | Installed by |
| --- | --- | --- | --- |
| `pu_fw8_fork1` | 889,232 | `3f68bee76f507878cd3e083a8b49ebb39932dd5f360329321bbc5614178e87e2` | fw 8.00 fork, commits `27c52ee`..`8818a3f` (builds fw8-dev-34..36) |

Older upstream readers (beta.1/beta.2 and earlier development builds) are
already pinned in the same list.

## Reader currently shipped (pin this before the next reader change)

| Size (bytes) | SHA-256 | Shipped by |
| --- | --- | --- |
| 889,616 | `3fe0a7a45df0e3175370f6578aed690c3064365e2948bd42ace3e527f14e5f75` | adaptive read-ahead builds (fw8-dev-37 diagnostic, fw8-rel-37 release) |

Its backup is `build/backups/readers/libSceAmpr-fw8-37-3fe0a7a4.sprx`. Move
this row into the pinned table, as `pu_fw8_fork2`, in the commit that next
changes the reader.
