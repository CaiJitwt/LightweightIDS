from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
from threading import Lock
from time import monotonic, sleep
from typing import Any


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("memory_load", wintypes.DWORD),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


class RuntimeHealthService:
    """Collect bounded host health metrics using only standard-library APIs."""

    def __init__(self, disk_path: str | Path) -> None:
        self.disk_path = Path(disk_path).resolve()
        self._cpu_lock = Lock()
        self._previous_cpu_sample: tuple[int, int] | None = None
        self._gpu_lock = Lock()
        self._last_gpu_sample: tuple[float | None, str] = (None, "")
        self._last_gpu_sample_at = 0.0

    def collect(self) -> dict[str, Any]:
        total_memory, available_memory = _memory_usage()
        disk = shutil.disk_usage(self.disk_path)
        gpu_percent, gpu_name = self._gpu_usage()
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "cpuPercent": self._cpu_percent(),
            "gpuPercent": gpu_percent,
            "gpuName": gpu_name,
            "logicalProcessors": os.cpu_count() or 1,
            "memoryUsedBytes": max(0, total_memory - available_memory),
            "memoryTotalBytes": total_memory,
            "diskUsedBytes": disk.used,
            "diskTotalBytes": disk.total,
            "diskFreeBytes": disk.free,
        }

    def _gpu_usage(self) -> tuple[float | None, str]:
        with self._gpu_lock:
            now = monotonic()
            if now - self._last_gpu_sample_at < 5.0:
                return self._last_gpu_sample
            self._last_gpu_sample = _nvidia_gpu_usage()
            self._last_gpu_sample_at = now
            return self._last_gpu_sample

    def _cpu_percent(self) -> float:
        if os.name != "nt":
            try:
                return round(min(100.0, os.getloadavg()[0] * 100 / max(os.cpu_count() or 1, 1)), 1)
            except (AttributeError, OSError):
                return 0.0
        with self._cpu_lock:
            current = _windows_cpu_sample()
            if self._previous_cpu_sample is None:
                self._previous_cpu_sample = current
                sleep(0.05)
                current = _windows_cpu_sample()
            previous_idle, previous_total = self._previous_cpu_sample
            idle, total = current
            self._previous_cpu_sample = current
        total_delta = total - previous_total
        if total_delta <= 0:
            return 0.0
        busy_delta = total_delta - (idle - previous_idle)
        return round(max(0.0, min(100.0, busy_delta * 100 / total_delta)), 1)


def _windows_cpu_sample() -> tuple[int, int]:
    idle = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        raise OSError("GetSystemTimes failed")
    idle_value = _filetime_value(idle)
    return idle_value, _filetime_value(kernel) + _filetime_value(user)


def _filetime_value(value: wintypes.FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _memory_usage() -> tuple[int, int]:
    if os.name == "nt":
        status = _MemoryStatus()
        status.length = ctypes.sizeof(_MemoryStatus)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx failed")
        return int(status.total_physical), int(status.available_physical)
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        total = page_size * int(os.sysconf("SC_PHYS_PAGES"))
        available = page_size * int(os.sysconf("SC_AVPHYS_PAGES"))
        return total, available
    except (AttributeError, OSError, ValueError):
        return 0, 0


def _nvidia_gpu_usage() -> tuple[float | None, str]:
    executable = shutil.which("nvidia-smi")
    if executable is None and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NVIDIA Corporation" / "NVSMI" / "nvidia-smi.exe"
        executable = str(candidate) if candidate.exists() else None
    if executable is None:
        return None, ""
    try:
        completed = subprocess.run(
            [executable, "--query-gpu=utilization.gpu,name", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, ""
    samples: list[tuple[float, str]] = []
    for line in completed.stdout.splitlines():
        utilization, separator, name = line.partition(",")
        if not separator:
            continue
        try:
            samples.append((max(0.0, min(100.0, float(utilization.strip()))), name.strip()))
        except ValueError:
            continue
    if not samples:
        return None, ""
    percent, name = max(samples, key=lambda item: item[0])
    return round(percent, 1), name
