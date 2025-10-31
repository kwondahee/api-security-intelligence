import argparse
import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

from lib.traffic import pump

def load_config(env_path: str):
    if env_path and Path(env_path).exists():
        load_dotenv(env_path)

    cfg = {
        "TARGET_BASE_URL": os.getenv("TARGET_BASE_URL", "http://localhost:8080"),
        "ACTORS": [s.strip() for s in os.getenv("ACTORS", "1,24,99").split(",") if s.strip()],
        "FLOWS": [s.strip().lower() for s in os.getenv("FLOWS", "all").split(",") if s.strip()],
        "RPS": int(os.getenv("RPS", "10")),
        "DURATION_SECONDS": int(os.getenv("DURATION_SECONDS", "60")),
        "ENABLE_SQLI": os.getenv("ENABLE_SQLI", "true").lower() in ("1","true","yes"),
        "ENABLE_XSS": os.getenv("ENABLE_XSS", "true").lower() in ("1","true","yes"),
        "ENABLE_TRAVERSAL": os.getenv("ENABLE_TRAVERSAL", "true").lower() in ("1","true","yes"),
        "LOG_JSON": os.getenv("LOG_JSON", "true").lower() in ("1","true","yes"),
        "LOG_PATH": os.getenv("LOG_PATH", ""),
        "MODE": os.getenv("MODE", "continuous"),  # continuous or oneshot
    }
    return cfg

def make_logger(log_path: str):
    if not log_path:
        return print
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    def _log(item):
        s = item if isinstance(item, str) else str(item)
        with p.open("a", encoding="utf-8") as f:
            f.write(s + "\n")
    return _log

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default="config/generator.env")
    args = parser.parse_args()

    cfg = load_config(args.env)
    logger = make_logger(cfg["LOG_PATH"]) if cfg["LOG_JSON"] else print

    print("Generator config:", {k: v for k, v in cfg.items() if k not in ("ACTORS","FLOWS")})
    summary = await pump(
        base_url=cfg["TARGET_BASE_URL"],
        flows=cfg["FLOWS"],
        actors=cfg["ACTORS"],
        rps=cfg["RPS"],
        duration_seconds=cfg["DURATION_SECONDS"],
        enable_sqli=cfg["ENABLE_SQLI"],
        enable_xss=cfg["ENABLE_XSS"],
        enable_traversal=cfg["ENABLE_TRAVERSAL"],
        log_json=cfg["LOG_JSON"],
        logger_print=logger,
    )
    print({"summary": summary})

if __name__ == "__main__":
    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass
    asyncio.run(main())
