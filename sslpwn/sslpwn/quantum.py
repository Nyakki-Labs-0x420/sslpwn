"""
Quantum acceleration module for sslpwn using OpenQuantum Qiskit provider.

All Qiskit transpilation and circuit building is offloaded to threads
to avoid blocking the asyncio event loop.
"""

import os
import logging
import math
import random
import time
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

try:
    from qiskit import QuantumCircuit, transpile
    from openquantum_sdk.qiskit import OpenQuantumService, SamplerV2, get_backend, list_backends
except ImportError as e:
    raise ImportError(
        "Qiskit or OpenQuantum Qiskit provider not installed. "
        "Please run: pip install qiskit openquantum-sdk-qiskit"
    ) from e


@dataclass
class QuantumJobResult:
    job_id: str
    status: str
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    submitted_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    backend_id: str = ""
    shots: int = 0


class QuantumAccelerator:
    def __init__(
        self,
        pDefaultBackend: Optional[str] = None,
        pDefaultShots: int = 1024,
        pTimeoutSeconds: int = 600,
    ) -> None:
        self._default_backend = pDefaultBackend or os.environ.get(
            "OPENQUANTUM_DEFAULT_BACKEND", "rigetti:cepheus-1-108q"
        )
        self._default_shots = pDefaultShots
        self._timeout_seconds = pTimeoutSeconds

        self._service: Optional[OpenQuantumService] = None
        self._backend = None
        self._initialize_service()

    def _initialize_service(self) -> None:
        try:
            self._service = OpenQuantumService()
            self._backend = get_backend(self._default_backend, service=self._service)
            logger.info("OpenQuantum Qiskit service initialized successfully.")
            logger.info(f"Backend: {self._default_backend}")
        except Exception as exc:
            logger.error("Failed to initialize OpenQuantum service: %s", exc)
            raise RuntimeError(f"OpenQuantum service initialization failed: {exc}") from exc

    def _submit_circuit_sync(
        self,
        pCircuit: QuantumCircuit,
        pBackendId: str,
        pShots: int,
        pWaitForCompletion: bool,
        pPollIntervalSeconds: float,
    ) -> QuantumJobResult:
        if self._service is None or self._backend is None:
            raise RuntimeError("OpenQuantum service not initialized.")

        if pBackendId != self._default_backend:
            backend = get_backend(pBackendId, service=self._service)
        else:
            backend = self._backend

        logger.info("Submitting circuit to backend: %s", pBackendId)
        logger.debug("Circuit:\n%s", pCircuit)

        try:
            transpiled_circuit = transpile(pCircuit, backend=backend)

            config = {
                "backend_class_id": pBackendId,
                "job_subcategory_id": "oth:oth",
                "name": f"sslpwn_shor_{int(time.time())}",
                "execution_plan": "auto",
                "queue_priority": "auto",
            }

            sampler = SamplerV2(
                backend=backend,
                scheduler=self._service.scheduler,
                config=config,
                export_format="qasm3",
            )

            job = sampler.run([(transpiled_circuit, None, pShots)])

            objResult = QuantumJobResult(
                job_id=job.job_id(),
                status="RUNNING",
                backend_id=pBackendId,
                shots=pShots,
            )

            logger.info("Job submitted successfully. Job ID: %s", objResult.job_id)

            if pWaitForCompletion:
                objResult = self._wait_for_completion_sync(objResult, pPollIntervalSeconds)

            return objResult

        except Exception as exc:
            logger.error("Failed to submit quantum job: %s", exc)
            return QuantumJobResult(
                job_id="",
                status="ERROR",
                error=str(exc),
                backend_id=pBackendId,
                shots=pShots,
            )

    def _wait_for_completion_sync(
        self,
        pJobResult: QuantumJobResult,
        pPollIntervalSeconds: float = 5.0,
    ) -> QuantumJobResult:
        if self._service is None:
            pJobResult.status = "ERROR"
            pJobResult.error = "Service not initialized"
            return pJobResult

        nElapsed = 0.0
        while nElapsed < self._timeout_seconds:
            try:
                job = self._service.scheduler.get_job(pJobResult.job_id)
                status = job.status()
                pJobResult.status = status

                if status in ("completed", "succeeded", "DONE", "COMPLETED"):
                    output = self._service.scheduler.download_job_output(job)
                    if isinstance(output, dict) and "counts" in output:
                        counts = output["counts"]
                    else:
                        counts = output.get("results", {}).get("counts", {}) if isinstance(output, dict) else {}
                    pJobResult.results = {"counts": counts}
                    pJobResult.completed_at = datetime.now()
                    logger.info("Job %s completed successfully.", pJobResult.job_id)
                    return pJobResult

                if status in ("failed", "cancelled", "error", "FAILED", "CANCELLED"):
                    pJobResult.error = f"Job terminated with status: {status}"
                    logger.error("Job %s failed with status: %s", pJobResult.job_id, status)
                    return pJobResult

                logger.debug("Job %s status: %s, waiting...", pJobResult.job_id, status)
                time.sleep(pPollIntervalSeconds)
                nElapsed += pPollIntervalSeconds

            except Exception as exc:
                logger.warning("Error polling job status: %s", exc)
                time.sleep(pPollIntervalSeconds)
                nElapsed += pPollIntervalSeconds

        pJobResult.status = "TIMEOUT"
        pJobResult.error = f"Job timed out after {self._timeout_seconds} seconds"
        logger.error("Job %s timed out.", pJobResult.job_id)
        return pJobResult

    async def submit_circuit_async(
        self,
        pCircuit: QuantumCircuit,
        pBackendId: Optional[str] = None,
        pShots: Optional[int] = None,
        pWaitForCompletion: bool = True,
        pPollIntervalSeconds: float = 5.0,
    ) -> QuantumJobResult:
        if self._service is None or self._backend is None:
            raise RuntimeError("OpenQuantum service not initialized.")

        sBackendId = pBackendId or self._default_backend
        nShots = pShots or self._default_shots

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            self._submit_circuit_sync,
            pCircuit,
            sBackendId,
            nShots,
            pWaitForCompletion,
            pPollIntervalSeconds,
        )
        return result

    def get_backends(self) -> List[Dict[str, Any]]:
        if self._service is None:
            return []
        try:
            backends = list_backends(service=self._service)
            return [{"name": b.name, "num_qubits": b.num_qubits} for b in backends]
        except Exception as exc:
            logger.error("Failed to list backends: %s", exc)
            return []

    def is_available(self) -> bool:
        if self._service is None:
            return False
        try:
            list_backends(service=self._service)
            return True
        except Exception:
            return False


# -----------------------------------------------------------------------------
# Shor's algorithm circuit generation
# -----------------------------------------------------------------------------

def build_shor_circuit(pN: int, pA: int) -> QuantumCircuit:
    n = math.ceil(math.log2(pN))
    t = 2 * n
    total_qubits = t + n + 2

    if total_qubits > 20:
        raise ValueError(
            f"Circuit requires {total_qubits} qubits, which exceeds the limit of 20. "
            f"N={pN} requires n={n}, t={t}."
        )

    qc = QuantumCircuit(total_qubits, t)

    for i in range(t):
        qc.h(i)

    qc.x(t)

    for i in range(t):
        multiplier = pow(pA, (1 << i), pN)
        if multiplier == 1:
            continue
        _add_controlled_modmul(qc, i, t, t + n, pN, multiplier, n)

    _inverse_qft(qc, 0, t)

    for i in range(t):
        qc.measure(i, i)

    return qc


def _add_controlled_modmul(qc: QuantumCircuit, control: int, target_start: int, mod_start: int, modulus: int, multiplier: int, num_bits: int) -> None:
    for i in range(num_bits):
        add_val = (multiplier * (1 << i)) % modulus
        if add_val == 0:
            continue
        for j in range(num_bits):
            if (add_val >> j) & 1:
                qc.ccx(control, target_start + i, target_start + j)
        for j in range(num_bits - 1, -1, -1):
            if (modulus >> j) & 1:
                qc.ccx(control, target_start + j, mod_start)
                qc.cx(mod_start, target_start + j)


def _inverse_qft(qc: QuantumCircuit, start: int, num_qubits: int) -> None:
    for i in range(num_qubits):
        for j in range(i):
            angle = -math.pi / (1 << (i - j))
            qc.cp(angle, start + j, start + i)
        qc.h(start + i)


def _continued_fractions(pX: int, pQ: int, pMaxDenom: int) -> List[Tuple[int, int]]:
    convergents = []
    a = pX
    b = pQ
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    while b != 0 and len(convergents) < 20:
        q = a // b
        a, b = b, a - q * b
        h0, h1 = h1, h0 + q * h1
        k0, k1 = k1, k0 + q * k0
        if k0 > pMaxDenom:
            break
        convergents.append((h0, k0))
    return convergents


def _find_period_from_counts(
    pCounts: Dict[str, int],
    pN: int,
    pA: int,
    pShots: int,
) -> Optional[int]:
    t = 2 * math.ceil(math.log2(pN))
    q = 1 << t
    if not pCounts:
        return None
    sorted_counts = sorted(pCounts.items(), key=lambda x: x[1], reverse=True)
    for bitstring, count in sorted_counts:
        if count < pShots * 0.05:
            continue
        try:
            y = int(bitstring, 2)
        except ValueError:
            continue
        if y == 0:
            continue
        for num, den in _continued_fractions(y, q, pN):
            if den == 0:
                continue
            if pow(pA, den, pN) == 1:
                return den
            for r in [den, 2 * den, 3 * den, 4 * den]:
                if r > 0 and r < pN and pow(pA, r, pN) == 1:
                    return r
    return None


def factor_rsa_with_quantum(
    pN: int,
    pAccelerator: QuantumAccelerator,
    pBackendId: Optional[str] = None,
    pShots: int = 1024,
) -> Optional[Tuple[int, int]]:
    if pN < 3 or pN % 2 == 0:
        return None

    n_bits = math.ceil(math.log2(pN))
    if n_bits > 5:
        logger.warning(
            f"N={pN} requires {n_bits} bits. This implementation supports N <= 31 "
            f"due to qubit constraints on available hardware."
        )
        return None

    for attempt in range(5):
        a = random.randint(2, pN - 2)
        while math.gcd(a, pN) != 1:
            a = random.randint(2, pN - 2)

        logger.info(f"Attempt {attempt + 1}: Using base a={a}")

        try:
            circuit = build_shor_circuit(pN, a)
            result = pAccelerator._submit_circuit_sync(
                circuit,
                pBackendId or pAccelerator._default_backend,
                pShots,
                True,
                5.0,
            )

            if result.status not in ("completed", "succeeded", "DONE", "COMPLETED"):
                logger.warning(f"Quantum job failed: {result.error}")
                continue

            counts = result.results.get("counts", {}) if result.results else {}
            if not counts:
                logger.warning("No measurement counts in results")
                continue

            r = _find_period_from_counts(counts, pN, a, pShots)
            if r is None:
                logger.warning("Could not find period from measurements")
                continue

            if r % 2 != 0:
                logger.warning(f"Period r={r} is odd, trying again")
                continue

            candidate1 = math.gcd(pow(a, r // 2) - 1, pN)
            candidate2 = math.gcd(pow(a, r // 2) + 1, pN)

            if candidate1 > 1 and candidate1 < pN:
                return (candidate1, pN // candidate1)
            if candidate2 > 1 and candidate2 < pN:
                return (candidate2, pN // candidate2)

            logger.warning(f"Factors not found from period r={r}")

        except Exception as exc:
            logger.warning(f"Quantum factoring attempt {attempt + 1} failed: {exc}")

    return None


_g_quantum_accelerator: Optional[QuantumAccelerator] = None


def get_quantum_accelerator() -> Optional[QuantumAccelerator]:
    global _g_quantum_accelerator
    if _g_quantum_accelerator is None:
        try:
            _g_quantum_accelerator = QuantumAccelerator()
        except Exception as exc:
            logger.warning("Failed to initialize QuantumAccelerator: %s", exc)
            return None
    return _g_quantum_accelerator
