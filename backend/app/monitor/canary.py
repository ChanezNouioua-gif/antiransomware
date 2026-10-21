"""Fichiers canari (honeypots) : des leurres que personne ne devrait modifier.

Toute modification, suppression ou renommage d'un canari est un signal quasi
certain (très peu de faux positifs) -> alerte immédiate.
"""

from pathlib import Path

CANARY_NAMES = [
    "!_documents_importants.txt",
    "000_sauvegarde_comptabilite.csv",
    "aaa_mots_de_passe_backup.txt",
    "zzz_contrats_clients.md",
]
CANARY_BODY = ("Fichier leurre - ne pas modifier.\n" * 40).encode()  # > 512 octets, entropie basse


class CanaryManager:
    def __init__(self, canary_dir: Path):
        self.dir = Path(canary_dir).resolve()

    def deploy(self) -> list[Path]:
        """Crée les leurres (à appeler AVANT de démarrer le watcher)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        paths = []
        for name in CANARY_NAMES:
            p = self.dir / name
            if not p.exists():
                p.write_bytes(CANARY_BODY)
            paths.append(p)
        return paths

    def is_canary(self, path: str | Path) -> bool:
        try:
            return Path(path).resolve().is_relative_to(self.dir)
        except OSError:
            return False
