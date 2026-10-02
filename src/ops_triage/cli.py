from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import PayloadError, adapt
from .app import Settings, build_pipeline
from .security import sign

SEV = {"P1": "🚨", "P2": "🔴", "P3": "🟠", "P4": "🔵"}


def _replay(args: argparse.Namespace) -> int:
    settings = Settings(db_path=":memory:", config_dir=args.config_dir, llm=args.llm, dry_run=True)
    pipeline = build_pipeline(settings)
    lines = [json.loads(line) for line in Path(args.events).read_text(encoding="utf-8").splitlines() if line.strip()]
    processed = duplicates = skipped = 0
    print(f"▶ Replaying {len(lines)} webhook payloads  (llm={args.llm}, dry-run: nothing is sent)\n")
    for item in lines:
        try:
            events = adapt(item["source"], item["payload"])
        except PayloadError as exc:
            print(f"  ✖ rejected: {exc}")
            continue
        if not events:
            skipped += 1
            print(f"  ⏭  {item['source']}: nothing to do (resolved / not an opened issue)")
            continue
        for event in events:
            out = pipeline.process(event)
            if out.status == "duplicate":
                duplicates += 1
                print(f"  ♻️  duplicate suppressed: {event.title[:60]}")
                continue
            processed += 1
            t = out.triage
            where = ", ".join(f"{d['destination']}" for d in out.deliveries) or "nowhere"
            flags = " 👤human" if t.needs_human else ""
            print(f"  {SEV[t.severity]} {t.severity} {t.category:<14} {t.team:<13} {t.confidence:>4.0%}{flags}  "
                  f"{event.title[:52]}")
            print(f"       → {where}")
            for note in t.policy_notes:
                print(f"       ⚖️  {note}")
            if out.redacted:
                print(f"       🔒 redacted before the LLM saw it: {', '.join(out.redacted)}")
    stats = pipeline.store.stats()
    print(f"\n✔ {processed} triaged · {duplicates} duplicates suppressed · {skipped} skipped · "
          f"{stats['needs_human']} need a human")
    print(f"  by severity: {stats['by_severity']}")
    print(f"  by category: {stats['by_category']}")
    return 0


def _sign(args: argparse.Namespace) -> int:
    print(sign(args.secret.encode(), Path(args.file).read_bytes()))
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-triage", description="AI ops triage and routing")
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="run sample webhook payloads through the full pipeline (dry run)")
    replay.add_argument("--events", default="samples/events.jsonl")
    replay.add_argument("--config-dir", default="config")
    replay.add_argument("--llm", choices=["heuristic", "openai"], default="heuristic")
    replay.set_defaults(func=_replay)

    signer = sub.add_parser("sign", help="compute the X-Signature-256 header for a payload file")
    signer.add_argument("file")
    signer.add_argument("--secret", required=True)
    signer.set_defaults(func=_sign)

    serve = sub.add_parser("serve", help="run the webhook service (configure with environment variables)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
