#!/usr/bin/env python3
"""Simulateur de comportement ransomware — OUTIL DE TEST pour le projet anti-ransomware.

Il reproduit uniquement la *signature comportementale* observable par le monitor
(rafale de modifications, entropie élevée, renommages) sur des fichiers factices
qu'il génère lui-même. À lancer dans une VM ou un dossier jetable.

Garde-fous (volontairement stricts) :
  * ne travaille que dans un dossier marqué par `init` (fichier .antiransom_sandbox) ;
  * ne touche que les fichiers listés dans son propre manifeste (créés par `init`) ;
  * refuse la racine, le dossier personnel et tout chemin trop court/large ;
  * aucun accès réseau, aucune persistance, aucune propagation ;
  * 100 % réversible : `restore` déchiffre et vérifie les empreintes SHA-256.

Usage :
  python scripts/ransomware_simulator.py init     --dir sandbox/watched --count 200
  python scripts/ransomware_simulator.py encrypt  --dir sandbox/watched --delay 0.01
  python scripts/ransomware_simulator.py restore  --dir sandbox/watched
  # scénarios bénins (doivent NE PAS déclencher d'incident) :
  python scripts/ransomware_simulator.py benign-zip   --dir sandbox/watched
  python scripts/ransomware_simulator.py benign-copy  --dir sandbox/watched
  python scripts/ransomware_simulator.py benign-edit  --dir sandbox/watched
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import string
import sys
import time
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MARKER = ".antiransom_sandbox"
MANIFEST = ".sim_manifest.json"
KEYFILE = ".sim_key"
MAX_FILES = 5000
LOCKED_EXT = ".locked"
EXTENSIONS = [".txt", ".csv", ".md", ".log.txt", ".json", ".docx.txt"]


# --------------------------------------------------------------------------- garde-fous
def resolve_sandbox(raw: str, must_exist_marker: bool = True) -> Path:
    path = Path(raw).expanduser().resolve()
    home = Path.home().resolve()
    if path == Path(path.anchor) or path == home or len(path.parts) < 3:
        sys.exit(f"REFUS : '{path}' est trop large (racine/dossier personnel).")
    if home.is_relative_to(path):
        sys.exit(f"REFUS : '{path}' contient le dossier personnel.")
    if must_exist_marker and not (path / MARKER).is_file():
        sys.exit(f"REFUS : '{path}' n'est pas un dossier sandbox (lance d'abord `init`).")
    return path


def load_manifest(sandbox: Path) -> dict:
    mf = sandbox / MANIFEST
    if not mf.is_file():
        sys.exit("REFUS : manifeste introuvable, rien à manipuler.")
    return json.loads(mf.read_text())


def save_manifest(sandbox: Path, data: dict) -> None:
    (sandbox / MANIFEST).write_text(json.dumps(data, indent=2))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_member(sandbox: Path, rel: str) -> Path:
    """Chemin d'un fichier du manifeste, garanti à l'intérieur de la sandbox."""
    p = (sandbox / rel).resolve()
    if not p.is_relative_to(sandbox):
        sys.exit(f"REFUS : chemin hors sandbox dans le manifeste : {rel}")
    return p


# --------------------------------------------------------------------------- commandes
def fake_text(rng: random.Random, size: int) -> bytes:
    words = ["facture", "client", "rapport", "budget", "projet", "contrat", "reunion",
             "alger", "donnees", "equipe", "livrable", "analyse", "securite", "audit"]
    out, total = [], 0
    while total < size:
        w = rng.choice(words) + rng.choice([" ", " ", ", ", ".\n"])
        out.append(w)
        total += len(w)
    return "".join(out).encode()[:size]


def cmd_init(args) -> None:
    if args.count > MAX_FILES:
        sys.exit(f"REFUS : --count max {MAX_FILES}.")
    sandbox = resolve_sandbox(args.dir, must_exist_marker=False)
    if sandbox.exists() and any(p.name not in (MARKER, MANIFEST, KEYFILE) for p in sandbox.iterdir()):
        sys.exit("REFUS : le dossier n'est pas vide. Utilise un dossier neuf dédié à la simulation.")
    sandbox.mkdir(parents=True, exist_ok=True)
    (sandbox / MARKER).write_text("dossier de simulation anti-ransomware - fichiers factices uniquement\n")
    rng = random.Random(args.seed)
    files = {}
    for i in range(args.count):
        sub = sandbox / f"dossier_{i % 8}"
        sub.mkdir(exist_ok=True)
        p = sub / f"document_{i:04d}{rng.choice(EXTENSIONS)}"
        p.write_bytes(fake_text(rng, rng.randint(2_000, 60_000)))
        files[str(p.relative_to(sandbox))] = sha256(p)
    save_manifest(sandbox, {"state": "clean", "files": files})
    print(f"{args.count} fichiers factices créés dans {sandbox}")


def cmd_encrypt(args) -> None:
    sandbox = resolve_sandbox(args.dir)
    mf = load_manifest(sandbox)
    if mf["state"] != "clean":
        sys.exit("REFUS : la sandbox n'est pas à l'état 'clean' (lance `restore` d'abord).")
    key = AESGCM.generate_key(bit_length=256)
    (sandbox / KEYFILE).write_bytes(key)  # clé conservée localement : tout est réversible
    aes = AESGCM(key)
    rels = list(mf["files"])
    random.Random(args.seed).shuffle(rels)
    t0 = time.time()
    for rel in rels:
        src = safe_member(sandbox, rel)
        data = src.read_bytes()
        nonce = os.urandom(12)
        dst = src.with_name(src.name + LOCKED_EXT)
        dst.write_bytes(nonce + aes.encrypt(nonce, data, None))  # octets bruts -> entropie ~8
        src.unlink()
        if args.delay:
            time.sleep(args.delay)
    mf["state"] = "encrypted"
    save_manifest(sandbox, mf)
    dt = time.time() - t0
    print(f"{len(rels)} fichiers 'chiffrés' en {dt:.2f}s ({len(rels)/max(dt,1e-9):.0f} fichiers/s)")


def cmd_restore(args) -> None:
    sandbox = resolve_sandbox(args.dir)
    mf = load_manifest(sandbox)
    if mf["state"] == "clean":
        print("Rien à restaurer.")
        return
    key = (sandbox / KEYFILE).read_bytes()
    aes = AESGCM(key)
    bad = 0
    for rel, digest in mf["files"].items():
        orig = safe_member(sandbox, rel)
        locked = orig.with_name(orig.name + LOCKED_EXT)
        if not locked.is_file():
            bad += 1
            continue
        blob = locked.read_bytes()
        orig.write_bytes(aes.decrypt(blob[:12], blob[12:], None))
        locked.unlink()
        if sha256(orig) != digest:
            bad += 1
    mf["state"] = "clean"
    save_manifest(sandbox, mf)
    (sandbox / KEYFILE).unlink(missing_ok=True)
    print("Restauration terminée." if not bad else f"Restauration terminée avec {bad} anomalie(s).")


def _clean_files(sandbox: Path) -> list[Path]:
    mf = load_manifest(sandbox)
    if mf["state"] != "clean":
        sys.exit("REFUS : sandbox pas à l'état 'clean'.")
    return [safe_member(sandbox, rel) for rel in mf["files"]]


def cmd_benign_zip(args) -> None:
    """Archivage légitime : produit un .zip à forte entropie, mais ne modifie aucun original."""
    sandbox = resolve_sandbox(args.dir)
    files = _clean_files(sandbox)
    out = sandbox / "archive_sauvegarde.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, p.relative_to(sandbox))
            if args.delay:
                time.sleep(args.delay)
    print(f"Archive créée : {out.name} ({out.stat().st_size} octets)")


def cmd_benign_copy(args) -> None:
    """Copie en masse (sauvegarde) vers un sous-dossier : beaucoup de créations, entropie basse."""
    sandbox = resolve_sandbox(args.dir)
    files = _clean_files(sandbox)
    dest = sandbox / "copie_sauvegarde"
    dest.mkdir(exist_ok=True)
    for p in files:
        shutil.copy2(p, dest / p.name)
        if args.delay:
            time.sleep(args.delay)
    print(f"{len(files)} fichiers copiés dans {dest.name}/")


def cmd_benign_edit(args) -> None:
    """Édition en masse de texte (ex. refactoring) : modifications nombreuses, entropie basse.

    Le contenu est modifié puis rétabli à l'identique pour que la sandbox reste cohérente."""
    sandbox = resolve_sandbox(args.dir)
    files = _clean_files(sandbox)
    for p in files:
        original = p.read_bytes()
        p.write_bytes(original + b"\n# edite\n")
        p.write_bytes(original)
        if args.delay:
            time.sleep(args.delay)
    print(f"{len(files)} fichiers édités puis rétablis.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("init", cmd_init), ("encrypt", cmd_encrypt), ("restore", cmd_restore),
                     ("benign-zip", cmd_benign_zip), ("benign-copy", cmd_benign_copy),
                     ("benign-edit", cmd_benign_edit)]:
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True, help="dossier sandbox dédié")
        p.set_defaults(func=fn)
        if name == "init":
            p.add_argument("--count", type=int, default=200)
        if name != "restore" and name != "init":
            p.add_argument("--delay", type=float, default=0.0, help="pause (s) entre fichiers pour régler le débit")
        if name in ("init", "encrypt"):
            p.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
