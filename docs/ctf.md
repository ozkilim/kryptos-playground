# Paradigm Kryptos CTF (PK1–PK10)

Paradigm's practice puzzles, captured from https://paradigm.xyz/kryptos-ctf on 2026-11-15. All ten prizes are already won, but checking is still **free and unlimited** (sign in with X, type the answer into the letter boxes, click Decrypt). That makes them the ideal **free external check** for our methods before we spend dollars on K4.

| Puzzle | Letters | `triage` guess | Status here | Prize won by |
|---|---|---|---|---|
| PK1 | 192 | periodic, period 10 | **cracked**: Vigenère, KRYPTOS alphabet, key PROVENANCE | @0xf4d3, 12 Jun 2026 |
| PK2 | 350 | transposition | **cracked**: 7-column columnar, order [3,0,5,1,2,4,6] | @98_akr, 12 Jun |
| PK3 | 280 | flat | open | @zhygis, 12 Jun |
| PK4 | 224 | flat | open | @98_akr, 12 Jun |
| PK5 | 272 | flat | open | @0xtanishk, 12 Jun |
| PK6 | 315 | periodic, period 12 (missing P) | open: plain Vigenère fails, try an unknown keyed alphabet (Quagmire) | @98_akr, 12 Jun |
| PK7 | 279 | flat | open | @crook3dfingers, 13 Jun |
| PK8 | 153 | flat | open | @_newhaiku, 6 Sep |
| PK9 | 144 | weakly periodic, ~14 | open | @LazlosBatForm, 2 Oct |
| PK10 | 504 | flat | open | @forwardsecrecy, 2 Oct |

PK1 and PK2 were cracked blind by `python -m kryptos crack pk1` / `pk2`. They read as clean English (a story about a knot and the lost archive of "Pellegrin"), but haven't been confirmed on the site yet. Once confirmed, set `"status": "solved"` in `data/ctf/pkN.json`.

The puzzles seem to get harder with the number, and the plaintexts tell a running story, so cracked ones may hold hints (keys, names) for later ones.

Run `python -m kryptos triage all` for live numbers.
