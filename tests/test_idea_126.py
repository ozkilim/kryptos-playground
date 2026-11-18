"""Planted test for idea 126: a 20-letter instruction hidden in word initials of K2 is found by the
reading battery and beats every word-shuffled control (one unit, few controls, so it runs fast)."""
import random
import _runner  # noqa: F401

from kryptos.idea126_hidden import (Scorer, build_specs, describe, panel_cells, plant, readings_text,
                                    real_sections, run_test)


def test_panel_rows_cover_k1_k3():
    rows = panel_cells()
    assert len(rows) == 25
    cells = [c for r in rows for c in r]
    assert cells == list(range(768))


def test_word_run_score():
    sc = Scorer()
    assert sc.stats("QXSHIFTEACHROWBYTHEKEYZQ")[5] == 20
    assert sc.stats("XQZJVKWPLMNRTSBCDFGH")[5] == 0


def test_planted_initials_found():
    sec = real_sections()
    msg = "SHIFTEACHROWBYTHEKEY"
    ptext = plant(sec, msg, "K2", 1, 1, 30, random.Random(126))
    specs = build_specs(ptext, only=("K2[carved,Xkept,ROWS]",))
    assert any(msg in r for _, r in readings_text(ptext, specs))
    res = run_test(ptext, 8, 16, seed0=500, only=("K2[carved,Xkept,ROWS]",), procs=2, log=lambda *a: None)
    lab, txt = describe(ptext, res["specs"], res["top"][0]["reading"])
    assert msg in txt, (lab, txt)
    assert res["comb_ge"] == 0
    word_run = [p for p in res["per_channel"] if p["channel"] == "word:wordrun"][0]
    assert word_run["real"] >= 20 and word_run["ctrl_max"] < 20


if __name__ == "__main__":
    _runner.run(globals())
