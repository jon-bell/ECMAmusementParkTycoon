# Input corpus

Each file is an oracle input script (format: `oracle/README.md`). A case is identified by its
path. Scenario numbers are the game's own (`Scenarios/SC<n>.SC4`); 0–4 are the scenarios the
shipped game unlocks at first start (Forest Frontiers, Dynamite Dunes, Leafy Lake, Diamond
Heights, Evergreen Gardens).

- `public/`  cases that porting work may run, read and debug against.
- `heldout/` cases that porting work never sees (principle 7). The determinism gate runs them
  because they test the oracle, not a port; a port is scored on them only at acceptance.

`seed` sets the virtual clock at process start. The scenario RNG seed is
`timeGetTime() ^ srand0` at the moment the scenario starts (0x43054E), so distinct seeds give
distinct parks from the same scenario.
