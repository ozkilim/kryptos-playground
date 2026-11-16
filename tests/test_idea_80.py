"""Idea 80: German sentence keys on keyword tableaux. The repository has no German model, so the tests cover
the missing-file report and the scoring machinery on a stand-in language."""
import random
import _runner  # noqa: F401

from kryptos import idea80_german as g
from kryptos.round9 import keyword_alphabet

WORDS = ["SHADOW", "MEDUSA", "PALIMPSEST", "ABSCISSA", "BERLIN", "EGYPT", "LODESTONE", "COMPASS", "CLOCK",
         "LUCID", "INVISIBLE", "MAGNETIC", "LANGLEY", "DIGETAL", "ILLUSION", "QUARTZ"]
ALPHAS = [(w, keyword_alphabet(w)) for w in WORDS]
GERMAN = ("Die Weltzeituhr auf dem Alexanderplatz zeigt die Zeit in allen Ländern der Erde. Über der Uhr drehen "
          "sich die Planeten, und viele Menschen treffen sich hier, weil jeder in Berlin diesen Ort kennt. Im "
          "Herbst des Jahres neunzehnhundertneunundachtzig gingen Hunderttausende auf die Straße, und in der "
          "Nacht öffnete sich die Mauer zwischen Ost und West. Niemand hatte geglaubt, daß es so schnell geht.")


def test_german_letters():
    assert g.german_letters("Über die Straße, Öl & Äpfel") == "UEBERDIESTRASSEOELAEPFEL"


def test_no_german_model_in_repository():
    # When this starts to fail, a German table has arrived: run attacks/80_german_sentence_keys.py for real.
    model, text = g.find_german()
    assert model is None and text is None, (model, text)


def test_table_file_round_trip(tmp_path):
    p = tmp_path / "q.txt"
    p.write_text("# test\nEINE 30\nSCHE 10\n")
    tab = g.table_from_file(p)
    idx = lambda q: ((ord(q[0]) - 65) * 26 + ord(q[1]) - 65) * 676 + (ord(q[2]) - 65) * 26 + ord(q[3]) - 65  # noqa: E731
    assert tab[idx("EINE")] > tab[idx("SCHE")] > tab[idx("QXQX")]


def test_planted_german_key_recovered():
    """A German sentence key on a keyword tableau: the true alphabet's forced key letters score best."""
    key_text = g.german_letters(GERMAN)
    tab = g.table_from_text(GERMAN)
    rng = random.Random(80)
    for kind in ("Q3", "Q1", "Q3", "Q1"):
        ct, cribs, w, key = g.plant(rng, ALPHAS, key_text, kind)
        top = g.score_alphabets(ALPHAS, ct, cribs, tab)
        assert keyword_alphabet(top[0][1]) == keyword_alphabet(w), (kind, w, top[0])
        assert key[21:34] + "|" + key[63:74] == top[0][4], (key, top[0])


if __name__ == "__main__":
    _runner.run(globals())
