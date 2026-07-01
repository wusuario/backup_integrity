#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

CHUNK_SIZE = 1024 * 1024
DEFAULT_MANIFEST = "backup-manifest.json"
DEFAULT_LOG = "backup-verify.log"
DEFAULT_ALGO = "blake2b"
DEFAULT_DIGEST_SIZE = 32


@dataclass
class FileEntry:
    path: str
    size: int
    mtime_ns: int
    checksum: str


@dataclass
class ScanResult:
    entries: Dict[str, FileEntry]
    file_count: int
    total_bytes: int
    errors: List[str]


@dataclass
class FileHashProgress:
    bytes_read: int
    total_bytes: int


class ProgressReporter:
    def __init__(self, label: str, total_files: int, total_bytes: int, enabled: bool = True) -> None:
        self.label = label
        self.total_files = total_files
        self.total_bytes = total_bytes
        self.enabled = enabled
        self.processed_files = 0
        self.processed_bytes = 0
        self.current_file = ""
        self.current_file_size = 0
        self.current_file_bytes = 0
        self.last_print = 0.0
        self.start_time = time.monotonic()
        self.finalized = False

    def start(self) -> None:
        if not self.enabled:
            return
        print(
            f"{self.label}: {self.total_files} arquivos, {format_size(self.total_bytes)} para processar.",
            flush=True,
        )

    def start_file(self, rel_path: str, size: int, index: int) -> None:
        self.current_file = rel_path
        self.current_file_size = size
        self.current_file_bytes = 0
        self._render(index=index, force=True)

    def update_file(self, file_bytes_read: int, index: int) -> None:
        self.current_file_bytes = file_bytes_read
        self._render(index=index, force=False)

    def finish_file(self, size: int, index: int) -> None:
        self.processed_files += 1
        self.processed_bytes += size
        self.current_file_bytes = size
        self._render(index=index, force=True)

    def message(self, text: str) -> None:
        if not self.enabled:
            return
        self._clear_line()
        print(text, flush=True)

    def finish(self) -> None:
        if not self.enabled or self.finalized:
            return
        self._clear_line()
        elapsed = max(time.monotonic() - self.start_time, 0.001)
        rate = self.processed_bytes / elapsed if self.processed_bytes else 0.0
        print(
            f"{self.label}: concluído. {self.processed_files}/{self.total_files} arquivos, "
            f"{format_size(self.processed_bytes)} em {format_duration(elapsed)} "
            f"({format_size(rate)}/s).",
            flush=True,
        )
        self.finalized = True

    def _render(self, index: int, force: bool) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self.last_print) < 0.2:
            return
        self.last_print = now

        overall_done = self.processed_bytes + self.current_file_bytes
        overall_pct = (overall_done / self.total_bytes * 100.0) if self.total_bytes else 100.0
        file_pct = (self.current_file_bytes / self.current_file_size * 100.0) if self.current_file_size else 100.0
        elapsed = max(now - self.start_time, 0.001)
        rate = overall_done / elapsed if overall_done else 0.0
        remaining = max(self.total_bytes - overall_done, 0)
        eta = (remaining / rate) if rate > 0 else 0
        display_name = shorten_middle(self.current_file, 70)

        line = (
            f"\r{self.label}: arquivo {min(index, self.total_files)}/{self.total_files} | "
            f"total {overall_pct:6.2f}% ({format_size(overall_done)}/{format_size(self.total_bytes)}) | "
            f"arquivo {file_pct:6.2f}% | {format_size(rate)}/s | ETA {format_duration(eta)} | {display_name}"
        )
        print(line, end="", flush=True)

    def _clear_line(self) -> None:
        print("\r" + (" " * 180) + "\r", end="", flush=True)


class CompareProgressReporter:
    def __init__(self, label: str, total_items: int, enabled: bool = True) -> None:
        self.label = label
        self.total_items = total_items
        self.enabled = enabled
        self.processed_items = 0
        self.changed_count = 0
        self.last_print = 0.0
        self.start_time = time.monotonic()
        self.finalized = False

    def start(self) -> None:
        if not self.enabled:
            return
        print(f"{self.label}: {self.total_items} arquivos em comum para comparar.", flush=True)

    def step(self, rel_path: str, changed_count: int, force: bool = False) -> None:
        self.processed_items += 1
        self.changed_count = changed_count
        self._render(rel_path=rel_path, force=force)

    def finish(self) -> None:
        if not self.enabled or self.finalized:
            return
        self._clear_line()
        elapsed = max(time.monotonic() - self.start_time, 0.001)
        rate = self.processed_items / elapsed if self.processed_items else 0.0
        print(
            f"{self.label}: concluído. {self.processed_items}/{self.total_items} arquivos comparados, "
            f"{self.changed_count} alterados encontrados em {format_duration(elapsed)} "
            f"({rate:.1f} arquivos/s).",
            flush=True,
        )
        self.finalized = True

    def _render(self, rel_path: str, force: bool) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self.last_print) < 0.2:
            return
        self.last_print = now

        pct = (self.processed_items / self.total_items * 100.0) if self.total_items else 100.0
        elapsed = max(time.monotonic() - self.start_time, 0.001)
        rate = self.processed_items / elapsed if self.processed_items else 0.0
        remaining = max(self.total_items - self.processed_items, 0)
        eta = (remaining / rate) if rate > 0 else 0
        display_name = shorten_middle(rel_path, 70)
        line = (
            f"\r{self.label}: {self.processed_items}/{self.total_items} | {pct:6.2f}% | "
            f"alterados até agora: {self.changed_count} | {rate:.1f} arquivos/s | "
            f"ETA {format_duration(eta)} | {display_name}"
        )
        print(line, end="", flush=True)

    def _clear_line(self) -> None:
        print("\r" + (" " * 180) + "\r", end="", flush=True)


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def format_size(num_bytes: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def format_duration(seconds: float) -> str:
    total = max(int(seconds), 0)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def shorten_middle(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    left = (max_len - 3) // 2
    right = max_len - 3 - left
    return f"{text[:left]}...{text[-right:]}"


def hash_file(
    path: Path,
    algorithm: str,
    digest_size: int,
    on_progress: Optional[Callable[[FileHashProgress], None]] = None,
) -> str:
    if algorithm == "blake2b":
        h = hashlib.blake2b(digest_size=digest_size)
    elif algorithm == "blake2s":
        h = hashlib.blake2s(digest_size=min(digest_size, 32))
    else:
        h = hashlib.new(algorithm)

    total_bytes = path.stat().st_size
    bytes_read = 0

    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            bytes_read += len(chunk)
            if on_progress:
                on_progress(FileHashProgress(bytes_read=bytes_read, total_bytes=total_bytes))
    return h.hexdigest()


def build_file_list(root: Path, exclude_names: set[str]) -> List[Path]:
    files: List[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name in exclude_names:
            continue
        files.append(path)
    return files


def scan_directory(
    root: Path,
    algorithm: str,
    digest_size: int,
    exclude_names: set[str],
    progress_label: str,
    show_progress: bool = True,
) -> ScanResult:
    entries: Dict[str, FileEntry] = {}
    errors: List[str] = []
    file_count = 0
    total_bytes = 0

    # Inicialização da Thread de animação dinâmica para diretórios robustos
    if show_progress:
        stop_anim_event = threading.Event()
        def _animate_initialization() -> None:
            print("Inicializando", end="", flush=True)
            while not stop_anim_event.wait(1.0):
                print(".", end="", flush=True)
            print(flush=True)  # Quebra de linha ao finalizar

        anim_thread = threading.Thread(target=_animate_initialization)
        anim_thread.start()

    try:
        files = build_file_list(root, exclude_names)
        planned_total_bytes = 0
        for file_path in files:
            try:
                planned_total_bytes += file_path.stat().st_size
            except Exception:
                pass
    finally:
        if show_progress:
            stop_anim_event.set()
            anim_thread.join()

    reporter = ProgressReporter(
        label=progress_label,
        total_files=len(files),
        total_bytes=planned_total_bytes,
        enabled=show_progress,
    )
    reporter.start()

    for index, file_path in enumerate(files, start=1):
        rel = file_path.relative_to(root).as_posix()
        try:
            stat = file_path.stat()
            reporter.start_file(rel, stat.st_size, index)
            checksum = hash_file(
                file_path,
                algorithm,
                digest_size,
                on_progress=lambda p, idx=index: reporter.update_file(p.bytes_read, idx),
            )
            entry = FileEntry(
                path=rel,
                size=stat.st_size,
                mtime_ns=getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)),
                checksum=checksum,
            )
            entries[rel] = entry
            file_count += 1
            total_bytes += stat.st_size
            reporter.finish_file(stat.st_size, index)
        except Exception as exc:
            errors.append(f"ERRO_LEITURA | {rel} | {exc}")
            reporter.message(f"Aviso: erro ao ler {rel} | {exc}")

    reporter.finish()
    return ScanResult(entries=entries, file_count=file_count, total_bytes=total_bytes, errors=errors)


def save_manifest(root: Path, manifest_path: Path, scan: ScanResult, algorithm: str, digest_size: int) -> None:
    data = {
        "version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(root.resolve()),
        "algorithm": algorithm,
        "digest_size": digest_size,
        "file_count": scan.file_count,
        "total_bytes": scan.total_bytes,
        "files": [
            {
                "path": entry.path,
                "size": entry.size,
                "mtime_ns": entry.mtime_ns,
                "checksum": entry.checksum,
            }
            for entry in sorted(scan.entries.values(), key=lambda e: e.path.lower())
        ],
        "scan_errors": scan.errors,
    }
    manifest_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_manifest(manifest_path: Path) -> Tuple[dict, Dict[str, FileEntry]]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    files: Dict[str, FileEntry] = {}
    for item in data.get("files", []):
        files[item["path"]] = FileEntry(
            path=item["path"],
            size=int(item["size"]),
            mtime_ns=int(item.get("mtime_ns", 0)),
            checksum=item["checksum"],
        )
    return data, files


def write_log(
    log_path: Path,
    root: Path,
    manifest_path: Path,
    summary: dict,
    deleted: List[str],
    added: List[str],
    changed: List[Tuple[str, str, str]],
    errors: List[str],
) -> None:
    now = datetime.now().astimezone().isoformat()
    lines: List[str] = []
    lines.append(f"Verificação executada em: {now}")
    lines.append(f"Diretório verificado: {root.resolve()}")
    lines.append(f"Manifesto usado: {manifest_path.resolve()}")
    lines.append("")
    lines.append("Resumo")
    lines.append(f"- Arquivos no manifesto: {summary['manifest_count']}")
    lines.append(f"- Arquivos encontrados agora: {summary['current_count']}")
    lines.append(f"- Corrompidos/alterados: {len(changed)}")
    lines.append(f"- Deletados: {len(deleted)}")
    lines.append(f"- Acrescentados: {len(added)}")
    lines.append(f"- Erros de leitura: {len(errors)}")
    lines.append("")

    lines.append("[CORROMPIDOS_OU_ALTERADOS]")
    if changed:
        for rel, old_hash, new_hash in changed:
            lines.append(rel)
            lines.append(f"  manifesto: {old_hash}")
            lines.append(f"  atual:     {new_hash}")
    else:
        lines.append("Nenhum")
    lines.append("")

    lines.append("[DELETADOS]")
    lines.extend(deleted or ["Nenhum"])
    lines.append("")

    lines.append("[ACRESCENTADOS]")
    lines.extend(added or ["Nenhum"])
    lines.append("")

    lines.append("[ERROS_DE_LEITURA]")
    lines.extend(errors or ["Nenhum"])
    lines.append("")

    log_path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(
    csv_path: Path,
    deleted: List[str],
    added: List[str],
    changed: List[Tuple[str, str, str]],
    errors: List[str],
) -> None:
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["tipo", "caminho", "hash_manifesto", "hash_atual", "detalhe"])
        for rel in deleted:
            writer.writerow(["deletado", rel, "", "", "ausente no diretório atual"])
        for rel in added:
            writer.writerow(["acrescentado", rel, "", "", "não existia no manifesto"])
        for rel, old_hash, new_hash in changed:
            writer.writerow(["alterado", rel, old_hash, new_hash, "checksum diferente"])
        for err in errors:
            writer.writerow(["erro_leitura", "", "", "", err])


def cmd_generate(args: argparse.Namespace) -> int:
    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        eprint(f"Diretório inválido: {root}")
        return 2

    manifest_path = Path(args.output).expanduser().resolve() if args.output else root / DEFAULT_MANIFEST
    exclude_names = {manifest_path.name}
    if args.exclude_log:
        exclude_names.add(Path(args.exclude_log).name)
    if args.exclude_csv:
        exclude_names.add(Path(args.exclude_csv).name)

    scan = scan_directory(
        root,
        args.algorithm,
        args.digest_size,
        exclude_names,
        progress_label="Gerando manifesto",
        show_progress=not args.no_progress,
    )
    save_manifest(root, manifest_path, scan, args.algorithm, args.digest_size)

    print(f"Manifesto criado: {manifest_path}")
    print(f"Arquivos processados: {scan.file_count}")
    print(f"Total de bytes: {scan.total_bytes}")
    if scan.errors:
        print(f"Erros de leitura: {len(scan.errors)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        eprint(f"Diretório inválido: {root}")
        return 2

    manifest_path = Path(args.manifest).expanduser().resolve() if args.manifest else root / DEFAULT_MANIFEST
    if not manifest_path.is_file():
        eprint(f"Manifesto não encontrado: {manifest_path}")
        return 2

    log_path = Path(args.log).expanduser().resolve() if args.log else root / DEFAULT_LOG
    csv_path = Path(args.csv).expanduser().resolve() if args.csv else root / (log_path.stem + ".csv")

    data, manifest_entries = load_manifest(manifest_path)
    algorithm = data.get("algorithm", DEFAULT_ALGO)
    digest_size = int(data.get("digest_size", DEFAULT_DIGEST_SIZE))

    exclude_names = {manifest_path.name, log_path.name, csv_path.name}
    current = scan_directory(
        root,
        algorithm,
        digest_size,
        exclude_names,
        progress_label="Verificando arquivos",
        show_progress=not args.no_progress,
    )

    manifest_paths = set(manifest_entries)
    current_paths = set(current.entries)

    deleted = sorted(manifest_paths - current_paths, key=str.lower)
    added = sorted(current_paths - manifest_paths, key=str.lower)
    common_paths = sorted(manifest_paths & current_paths, key=str.lower)
    changed: List[Tuple[str, str, str]] = []

    compare_reporter = CompareProgressReporter(
        label="Comparando com o manifesto",
        total_items=len(common_paths),
        enabled=not args.no_progress,
    )
    compare_reporter.start()

    for index, rel in enumerate(common_paths, start=1):
        old = manifest_entries[rel]
        new = current.entries[rel]
        if old.checksum != new.checksum:
            changed.append((rel, old.checksum, new.checksum))
        compare_reporter.step(
            rel_path=rel,
            changed_count=len(changed),
            force=(index == 1 or index == len(common_paths)),
        )

    compare_reporter.finish()

    errors = list(current.errors)
    summary = {
        "manifest_count": len(manifest_entries),
        "current_count": len(current.entries),
    }

    write_log(log_path, root, manifest_path, summary, deleted, added, changed, errors)
    write_csv(csv_path, deleted, added, changed, errors)

    print(f"Verificação concluída. Log: {log_path}")
    print(f"Relatório CSV: {csv_path}")
    print(f"Corrompidos/alterados: {len(changed)}")
    print(f"Deletados: {len(deleted)}")
    print(f"Acrescentados: {len(added)}")
    print(f"Erros de leitura: {len(errors)}")

    return 1 if (changed or deleted or added or errors) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gera e verifica manifesto de integridade de arquivos usando BLAKE2."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("gerar", help="Gera um manifesto JSON com checksums.")
    gen.add_argument("directory", help="Diretório raiz a ser inventariado.")
    gen.add_argument(
        "-o",
        "--output",
        help="Caminho do manifesto JSON. Padrão: backup-manifest.json no diretório raiz.",
    )
    gen.add_argument(
        "-a",
        "--algorithm",
        default=DEFAULT_ALGO,
        choices=["blake2b", "blake2s", "sha256"],
        help="Algoritmo de hash. Padrão: blake2b.",
    )
    gen.add_argument(
        "-d",
        "--digest-size",
        type=int,
        default=DEFAULT_DIGEST_SIZE,
        help="Tamanho do digest em bytes para BLAKE2. Padrão: 32.",
    )
    gen.add_argument("--exclude-log", help="Nome de log a ignorar durante a geração.")
    gen.add_argument("--exclude-csv", help="Nome de CSV a ignorar durante a geração.")
    gen.add_argument("--no-progress", action="store_true", help="Desativa a exibição de progresso em tempo real.")
    gen.set_defaults(func=cmd_generate)

    ver = subparsers.add_parser("verificar", help="Compara o diretório atual com um manifesto salvo.")
    ver.add_argument("directory", help="Diretório raiz a ser verificado.")
    ver.add_argument(
        "-m",
        "--manifest",
        help="Caminho do manifesto JSON. Padrão: backup-manifest.json no diretório raiz.",
    )
    ver.add_argument(
        "-l",
        "--log",
        help="Caminho do arquivo de log. Padrão: backup-verify.log no diretório raiz.",
    )
    ver.add_argument(
        "--csv",
        help="Caminho do relatório CSV. Padrão: mesmo nome do log com extensão .csv.",
    )
    ver.add_argument("--no-progress", action="store_true", help="Desativa a exibição de progresso em tempo real.")
    ver.set_defaults(func=cmd_verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())