# Shortcuts. Everything is plain Python 3.9+, no installs needed.
PY ?= python3

.PHONY: help test list triage solved attacks k4
help:
	@echo "make test      run all tests (K1-K3 solved blind, harness, checks)"
	@echo "make list      every puzzle and its status"
	@echo "make triage    cipher-type stats for every puzzle"
	@echo "make solved    reproduce K1, K2, K3"
	@echo "make attacks   run the baseline K4 attacks (logs to experiments/ledger.csv)"
	@echo "make k4        show K4 with the clues lined up"

test:
	@if $(PY) -m pytest --version >/dev/null 2>&1; then $(PY) -m pytest -q; \
	else for f in tests/test_*.py; do $(PY) $$f || exit 1; done; fi

list:
	$(PY) -m kryptos list

triage:
	$(PY) -m kryptos triage all

solved:
	$(PY) solved/k1.py && $(PY) solved/k2.py && $(PY) solved/k3.py

attacks:
	$(PY) attacks/01_vigenere_wordlist.py
	$(PY) attacks/02_transposition_plus_vigenere.py

k4:
	$(PY) -m kryptos show k4
