from __future__ import annotations

import importlib.metadata
import platform
import shutil
import sys
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class EndpointStatus:
    name: str
    url: str
    available: bool
    detail: str


def package_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def detect_torch_device() -> str:
    try:
        import torch
    except Exception:
        return "cpu"

    if torch.cuda.is_available():
        return "cuda"
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def torch_summary() -> dict[str, object]:
    summary: dict[str, object] = {
        "installed": False,
        "version": None,
        "device": "cpu",
        "cuda_available": False,
        "mps_available": False,
        "cuda_device_count": 0,
    }
    try:
        import torch
    except Exception as exc:
        summary["error"] = str(exc)
        return summary

    summary["installed"] = True
    summary["version"] = torch.__version__
    summary["cuda_available"] = torch.cuda.is_available()
    summary["cuda_device_count"] = torch.cuda.device_count() if torch.cuda.is_available() else 0
    summary["mps_available"] = bool(hasattr(torch.backends, "mps") and torch.backends.mps.is_available())
    summary["device"] = detect_torch_device()
    if summary["cuda_available"]:
        summary["cuda_devices"] = [torch.cuda.get_device_name(index) for index in range(torch.cuda.device_count())]
    return summary


def check_endpoint(name: str, models_url: str, timeout: float = 2.0) -> EndpointStatus:
    request = Request(models_url, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return EndpointStatus(name, models_url, 200 <= response.status < 300, f"HTTP {response.status}")
    except URLError as exc:
        return EndpointStatus(name, models_url, False, str(exc.reason))
    except Exception as exc:
        return EndpointStatus(name, models_url, False, str(exc))


def doctor() -> dict[str, object]:
    torch_info = torch_summary()
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "torch": torch_info,
        "vllm_executable": shutil.which("vllm"),
        "vllm_version": package_version("vllm"),
        "ollama_executable": shutil.which("ollama"),
        "endpoints": [
            check_endpoint("vLLM", "http://localhost:8000/v1/models"),
            check_endpoint("Ollama", "http://localhost:11434/v1/models"),
        ],
    }


def select_rag_backend() -> tuple[str, str, str]:
    vllm = check_endpoint("vLLM", "http://localhost:8000/v1/models")
    if vllm.available:
        return (
            "vLLM",
            "http://localhost:8000/v1/chat/completions",
            "meta-llama/Llama-3.1-8B-Instruct",
        )

    ollama = check_endpoint("Ollama", "http://localhost:11434/v1/models")
    if ollama.available:
        return (
            "Ollama",
            "http://localhost:11434/v1/chat/completions",
            "llama3.1:8b",
        )

    raise RuntimeError(
        "No local RAG endpoint is available. Start vLLM on :8000 or Ollama on :11434, "
        "then rerun rag-auto."
    )


def print_doctor_report() -> None:
    report = doctor()
    torch_info = report["torch"]

    print(f"Python: {report['python']}")
    print(f"Platform: {report['platform']} ({report['machine']})")
    print(f"Torch installed: {torch_info['installed']}")
    print(f"Torch version: {torch_info.get('version')}")
    print(f"Auto retrieval device: {torch_info['device']}")
    print(f"CUDA available: {torch_info['cuda_available']} count={torch_info['cuda_device_count']}")
    if torch_info.get("cuda_devices"):
        print(f"CUDA devices: {', '.join(torch_info['cuda_devices'])}")
    print(f"Apple MPS available: {torch_info['mps_available']}")
    print(f"vLLM executable: {report['vllm_executable'] or 'not found'}")
    print(f"vLLM package: {report['vllm_version'] or 'not installed'}")
    print(f"Ollama executable: {report['ollama_executable'] or 'not found'}")

    for endpoint in report["endpoints"]:
        state = "available" if endpoint.available else "not available"
        print(f"{endpoint.name} endpoint: {state} ({endpoint.url}; {endpoint.detail})")

    print()
    if torch_info["device"] == "cuda":
        print("Suggested retrieval command: python VULDAT-RAG/run.py retrieve --device auto --top-k 20 --rank-limit 200")
        print("Suggested RAG backend: vLLM, if the vLLM endpoint is available.")
    else:
        print("Suggested retrieval command: python VULDAT-RAG/run.py retrieve --device auto --top-k 20 --rank-limit 200")
        print("Suggested local RAG backend: Ollama at http://localhost:11434/v1/chat/completions.")
