"""Idea 28: a small neural network as a cipher detective (a learned fingerprint).

Training a model on K4's own 97 letters can't work (it can only memorise
them). Instead: generate a large labelled set of synthetic K4-like
ciphertexts, 97 letters of English with EASTNORTHEAST / BERLINCLOCK in K4's
positions, encrypted by each of ~40 cipher families with random keys. Train
a small 1-D convolutional network to name the family from ciphertext + the
known clue letters. Then ask it about K4 (and about shuffled K4s as a
baseline). Held-out accuracy per family says which verdicts can be trusted.

Run with an interpreter that has torch (campaign uses /usr/bin/python3).
"""
import json
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch  # noqa: E402
import torch.nn as nn  # noqa: E402

from kryptos import CRIBS, K4  # noqa: E402
from kryptos import fingerprint as FP  # noqa: E402
from kryptos.campaign import SMOKE, report, shuffled  # noqa: E402
from kryptos.ciphers import AZ, KRYPTOS_ALPHABET  # noqa: E402
from kryptos.solvers import twokeys as TK  # noqa: E402

N_TRAIN, N_TEST, EPOCHS = (60, 20, 1) if SMOKE else (2500, 400, 8)
DEV = "mps" if torch.backends.mps.is_available() else "cpu"


def families(text):
    F = FP.families(text)

    def two_long(pt, rng):
        L1 = rng.randint(18, 25)
        L2 = rng.randint(L1 + 1, 26)
        return TK.plant(pt, rng, rng.choice([AZ, KRYPTOS_ALPHABET]), "vigenere", L1, L2)[0]

    def two_short(pt, rng):
        L1 = rng.randint(5, 11)
        L2 = rng.randint(L1 + 1, 16)
        return TK.plant(pt, rng, rng.choice([AZ, KRYPTOS_ALPHABET]), "vigenere", L1, L2)[0]
    F["two stacked keys, long (18-26)"] = two_long
    F["two stacked keys, short (5-16)"] = two_short
    return F


def encode(ct):
    """Channels: one-hot ciphertext (26) + one-hot known plaintext at clue positions (26) + clue mask (1)."""
    x = torch.zeros(53, 97)
    for i, c in enumerate(ct):
        x[AZ.index(c), i] = 1
    for i, p in CRIBS.items():
        x[26 + AZ.index(p), i] = 1
        x[52, i] = 1
    return x


class Net(nn.Module):
    def __init__(self, n_out):
        super().__init__()
        layers, ch = [], 53
        for dil in (1, 2, 4, 8, 16):
            layers += [nn.Conv1d(ch, 128, 5, padding=2 * dil, dilation=dil), nn.GELU(), nn.BatchNorm1d(128)]
            ch = 128
        self.conv = nn.Sequential(*layers)
        self.pos = nn.Parameter(torch.zeros(1, 128, 97))
        self.head = nn.Sequential(nn.Linear(256, 256), nn.GELU(), nn.Dropout(0.2), nn.Linear(256, n_out))

    def forward(self, x):
        h = self.conv(x) + self.pos
        return self.head(torch.cat([h.mean(-1), h.amax(-1)], 1))


def dataset(F, names, text, n, seed):
    rng = random.Random(seed)
    X, y = [], []
    for k, name in enumerate(names):
        for _ in range(n):
            ct = F[name](FP.k4_like_plaintext(text, rng), rng)
            X.append(encode(ct))
            y.append(k)
    return torch.stack(X), torch.tensor(y)


if __name__ == "__main__":
    t0 = time.time()
    torch.manual_seed(0)
    text = FP.english_windows()
    F = families(text)
    names = list(F)
    Xtr, ytr = dataset(F, names, text, N_TRAIN, 1)
    Xte, yte = dataset(F, names, text, N_TEST, 2)
    net = Net(len(names)).to(DEV)
    opt = torch.optim.AdamW(net.parameters(), lr=2e-3, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=3e-3, total_steps=EPOCHS * (len(Xtr) // 256 + 1))
    lossf = nn.CrossEntropyLoss()
    for ep in range(EPOCHS):
        net.train()
        perm = torch.randperm(len(Xtr))
        for b in range(0, len(Xtr), 256):
            idx = perm[b:b + 256]
            opt.zero_grad()
            loss = lossf(net(Xtr[idx].to(DEV)), ytr[idx].to(DEV))
            loss.backward()
            opt.step()
            sched.step()
        net.eval()
        with torch.no_grad():
            pred = torch.cat([net(Xte[b:b + 512].to(DEV)).argmax(1).cpu() for b in range(0, len(Xte), 512)])
        print(f"epoch {ep + 1}: test accuracy {(pred == yte).float().mean():.3f}", flush=True)
    per_family = {names[k]: round(float((pred[yte == k] == k).float().mean()), 3) for k in range(len(names))}
    with torch.no_grad():
        pk4 = torch.softmax(net(encode(K4)[None].to(DEV)), 1)[0].cpu()
        sh = torch.stack([encode(shuffled(K4, 2000 + s)) for s in range(200)])
        psh = torch.softmax(net(sh.to(DEV)), 1).cpu()
    order = pk4.argsort(descending=True)
    top = [{"family": names[k], "p_k4": round(float(pk4[k]), 4), "p_shuffled_mean": round(float(psh[:, k].mean()), 4),
            "heldout_accuracy": per_family[names[k]]} for k in order[:10].tolist()]
    sh_top = {}
    for k in psh.argmax(1).tolist():
        sh_top[names[k]] = sh_top.get(names[k], 0) + 1
    verdict = (f"K4 classified as '{top[0]['family']}' (p={top[0]['p_k4']}, that family's held-out accuracy "
               f"{top[0]['heldout_accuracy']}); overall held-out accuracy {float((pred == yte).float().mean()):.3f}. "
               f"Shuffled K4s are mostly called {max(sh_top, key=sh_top.get)!r}")
    report("28", name="SLM cipher detective", families=names, heldout_accuracy=round(float((pred == yte).float().mean()), 3),
           per_family_accuracy=per_family, k4_top=top, shuffled_argmax_counts=sh_top, verdict=verdict,
           train_per_family=N_TRAIN, epochs=EPOCHS, device=DEV, minutes=round((time.time() - t0) / 60, 1))
    print("[28]", verdict)
    for t in top[:8]:
        print("  ", t)
