"""Experimental OpenFHE CKKS backend.

A second CKKS implementation behind the same :class:`EncryptedSlotVec`
interface the audit primitives are written against, so the six circuits
can run on OpenFHE as well as TenSEAL and a verifier is not locked to a
single library. Loaded only when the ``openfhe`` Python package is
importable; otherwise this module registers nothing and the backend
reports ``available = False``.

Status: EXPERIMENTAL
-------------------
The elementwise CKKS algebra (add, sub, negate, ciphertext×plaintext,
ciphertext×scalar, ciphertext×ciphertext, full-vector sum, cyclic
rotation) maps directly onto OpenFHE's ``EvalAdd`` / ``EvalSub`` /
``EvalMult`` / ``EvalSum`` / ``EvalRotate`` and is implemented here.

``mm_pt`` (encrypted-vector × plaintext-matrix) is implemented for
**square** matrices via the Halevi–Shoup diagonal method, which keeps the
operation at one multiplicative level — matching the TenSEAL backend's
depth accounting so the primitives' declared depth budgets still hold.
This covers every primitive whose circuit uses only square transforms
(rotation permutations and the CDF / drift triangular matrices).
Rectangular ``mm_pt`` — used solely by encrypted concordance — raises
:class:`NotImplementedError` rather than emitting an unvalidated circuit;
see :func:`regaudit_fhe.fhe.backends.supported_matrix_kinds`.

Numerical equivalence against the plaintext oracles must be validated in
an environment with the native OpenFHE library installed (see the
``openfhe`` equivalence tests, which skip when the package is absent).

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import ArrayLike

from .._slot import MAX_DEPTH, DepthBudgetExceeded

try:
    import openfhe as _openfhe  # noqa: F401

    _HAVE_OPENFHE = True
except Exception:
    _HAVE_OPENFHE = False


def available() -> bool:
    return _HAVE_OPENFHE


def _require() -> None:
    if not _HAVE_OPENFHE:
        raise RuntimeError("OpenFHE is not installed. Install the `openfhe` Python package.")


@dataclass
class OpenFHEContext:
    """OpenFHE CKKS context for the d=6 audit budget.

    Holds the crypto-context, the key pair, and the set of rotation
    indices for which keys have been generated. As with the TenSEAL
    reference context this is a single-party (auditor-held-keys) object:
    the secret key is retained so rotation keys can be generated on demand
    for the slot counts each circuit needs.
    """

    cc: Any
    keys: Any
    n_slots: int
    scale_bits: int
    multiplicative_depth: int
    _rotation_indices: set[int] = field(default_factory=set)

    def ensure_rotation_keys(self, indices: list[int]) -> None:
        needed = sorted({int(k) for k in indices if int(k) != 0} - self._rotation_indices)
        if not needed:
            return
        self.cc.EvalRotateKeyGen(self.keys.secretKey, needed)
        self._rotation_indices.update(needed)

    def encrypt_vector(self, values: list[float]) -> Any:
        pt = self.cc.MakeCKKSPackedPlaintext(list(values))
        return self.cc.Encrypt(self.keys.publicKey, pt)

    def decrypt_vector(self, ct: Any, length: int) -> list[float]:
        pt = self.cc.Decrypt(ct, self.keys.secretKey)
        pt.SetLength(length)
        return [float(v) for v in pt.GetRealPackedValue()[:length]]

    def plaintext(self, values: list[float]) -> Any:
        return self.cc.MakeCKKSPackedPlaintext(list(values))


def build_d6_context(
    *,
    poly_modulus_degree: int | None = None,
    scale_bits: int = 40,
    multiplicative_depth: int = 8,
    batch_size: int = 1 << 13,
) -> OpenFHEContext:
    """Construct an OpenFHE CKKS context mirroring the TenSEAL d=6 setup.

    ``multiplicative_depth`` defaults to 8 to match the TenSEAL chain
    (``[60, 40×7, 60]`` → seven interior multiplicative levels plus
    headroom); the audit primitives consume at most six.

    By default the ring dimension is left to OpenFHE's parameter
    generator, which selects the smallest dimension that meets the
    128-bit ``HEStd_128_classic`` standard for the chosen depth and
    scaling size (forcing a non-compliant dimension is refused by
    OpenFHE). Pass ``poly_modulus_degree`` only to pin a specific,
    standards-compliant ring. ``batch_size`` is the number of packed
    slots the circuits use; it must be a power of two not exceeding half
    the ring dimension.
    """
    _require()
    from openfhe import (
        CCParamsCKKSRNS,
        GenCryptoContext,
        PKESchemeFeature,
        SecurityLevel,
    )

    n_slots = int(batch_size)
    params = CCParamsCKKSRNS()
    params.SetMultiplicativeDepth(int(multiplicative_depth))
    params.SetScalingModSize(int(scale_bits))
    params.SetBatchSize(n_slots)
    params.SetSecurityLevel(SecurityLevel.HEStd_128_classic)
    if poly_modulus_degree is not None:
        params.SetRingDim(int(poly_modulus_degree))

    cc = GenCryptoContext(params)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)

    return OpenFHEContext(
        cc=cc,
        keys=keys,
        n_slots=n_slots,
        scale_bits=int(scale_bits),
        multiplicative_depth=int(multiplicative_depth),
    )


def _as_list(value: Any, target_len: int) -> list[float]:
    if isinstance(value, np.ndarray):
        return [float(v) for v in value.tolist()]
    if isinstance(value, (list, tuple)):
        return [float(v) for v in value]
    return [float(value)] * target_len


@dataclass
class OpenFHESlotVec:
    """OpenFHE-backed analogue of :class:`EncryptedSlotVec`.

    Mirrors the TenSEAL slot-vector API one-to-one, including the
    multiplicative-depth bookkeeping the primitives assert against, so an
    audit circuit can run unchanged on either backend.
    """

    ciphertext: Any
    ctx: OpenFHEContext
    n: int
    depth: int = 0
    max_depth: int = MAX_DEPTH

    def __post_init__(self) -> None:
        if self.depth > self.max_depth:
            raise DepthBudgetExceeded(f"depth {self.depth} exceeds budget {self.max_depth}")

    @classmethod
    def encrypt(
        cls, ctx: OpenFHEContext, values: ArrayLike, max_depth: int = MAX_DEPTH
    ) -> OpenFHESlotVec:
        if not isinstance(ctx, OpenFHEContext):
            raise TypeError("encrypt(ctx, values) requires an OpenFHEContext")
        vals = [float(v) for v in np.asarray(values, dtype=float).ravel()]
        ct = ctx.encrypt_vector(vals)
        return cls(ciphertext=ct, ctx=ctx, n=len(vals), depth=0, max_depth=max_depth)

    def _wrap(self, ct: Any, *, depth: int, n: int | None = None) -> OpenFHESlotVec:
        return OpenFHESlotVec(
            ciphertext=ct,
            ctx=self.ctx,
            n=self.n if n is None else n,
            depth=depth,
            max_depth=self.max_depth,
        )

    def decrypt(self) -> list[float]:
        return self.ctx.decrypt_vector(self.ciphertext, self.n)

    def first_slot(self) -> float:
        return float(self.decrypt()[0])

    def copy(self) -> OpenFHESlotVec:
        # OpenFHE ciphertext operations return fresh objects rather than
        # mutating operands in place, so a structural copy is sufficient.
        return self._wrap(self.ciphertext, depth=self.depth)

    def __add__(self, other: OpenFHESlotVec | np.ndarray | float | list) -> OpenFHESlotVec:
        cc = self.ctx.cc
        if isinstance(other, OpenFHESlotVec):
            return self._wrap(
                cc.EvalAdd(self.ciphertext, other.ciphertext),
                depth=max(self.depth, other.depth),
            )
        pt = self.ctx.plaintext(_as_list(other, self.n))
        return self._wrap(cc.EvalAdd(self.ciphertext, pt), depth=self.depth)

    def __radd__(self, other: Any) -> OpenFHESlotVec:
        return self.__add__(other)

    def __sub__(self, other: OpenFHESlotVec | np.ndarray | float | list) -> OpenFHESlotVec:
        cc = self.ctx.cc
        if isinstance(other, OpenFHESlotVec):
            return self._wrap(
                cc.EvalSub(self.ciphertext, other.ciphertext),
                depth=max(self.depth, other.depth),
            )
        pt = self.ctx.plaintext(_as_list(other, self.n))
        return self._wrap(cc.EvalSub(self.ciphertext, pt), depth=self.depth)

    def __neg__(self) -> OpenFHESlotVec:
        return self._wrap(self.ctx.cc.EvalMult(self.ciphertext, -1.0), depth=self.depth)

    def mul_pt(self, plaintext: Any) -> OpenFHESlotVec:
        pt = self.ctx.plaintext(_as_list(plaintext, self.n))
        return self._wrap(self.ctx.cc.EvalMult(self.ciphertext, pt), depth=self.depth + 1)

    def mul_scalar(self, scalar: float) -> OpenFHESlotVec:
        return self._wrap(self.ctx.cc.EvalMult(self.ciphertext, float(scalar)), depth=self.depth)

    def mul_ct(self, other: OpenFHESlotVec) -> OpenFHESlotVec:
        return self._wrap(
            self.ctx.cc.EvalMult(self.ciphertext, other.ciphertext),
            depth=max(self.depth, other.depth) + 1,
        )

    def rotate(self, k: int) -> OpenFHESlotVec:
        """Cyclic slot rotation by ``k``: ``out[i] == in[(i + k) mod n]``.

        OpenFHE's native ``EvalRotate`` shifts over the whole packed batch
        rather than cyclically within the ``n`` used slots, so — to match
        :class:`regaudit_fhe._slot.SlotVec.rotate` semantics exactly — this
        is implemented as an ``mm_pt`` against a cyclic permutation matrix,
        consuming one multiplicative level (as the TenSEAL backend's
        rotation does).
        """
        k = int(k) % self.n if self.n else 0
        if k == 0:
            return self.copy()
        perm = np.zeros((self.n, self.n), dtype=float)
        for c in range(self.n):
            perm[(c + k) % self.n, c] = 1.0
        return self.mm_pt(perm)

    def sum_all(self) -> OpenFHESlotVec:
        """Sum of all slots, broadcast across the batch (``EvalSum``)."""
        return self._wrap(self.ctx.cc.EvalSum(self.ciphertext, self.ctx.n_slots), depth=self.depth)

    def mm_pt(self, matrix: Any) -> OpenFHESlotVec:
        """Encrypted-vector × plaintext-matrix product, ``out = v @ M``.

        Implemented with the Halevi–Shoup diagonal method for **square**
        matrices, consuming exactly one multiplicative level (each
        generalised diagonal is a single ciphertext×plaintext multiply and
        the diagonals are summed, not chained). Output ``out[j] = Σ_i
        v[i]·M[i][j]`` matches the TenSEAL backend's ``mm_pt`` semantics.

        Rectangular matrices are not yet supported on this backend; see the
        module docstring.
        """
        m = np.asarray(matrix, dtype=float)
        if m.ndim != 2:
            raise ValueError("mm_pt requires a 2-D matrix")
        rows, cols = m.shape
        if rows != cols:
            raise NotImplementedError(
                "OpenFHE backend supports only square mm_pt (diagonal method); "
                f"got {rows}x{cols}. Rectangular mm_pt (encrypted concordance) "
                "is pending — see regaudit_fhe.fhe.openfhe module docstring."
            )
        n = rows
        # out = A @ v with A = M^T  ->  out[j] = Σ_i M[i][j] v[i].
        #
        # Diagonal method over SIGNED shifts. OpenFHE's EvalRotate shifts
        # over the whole packed batch, not cyclically within n, but the
        # vector is zero-padded beyond slot n-1, so a shift reads zeros
        # where it leaves the n-block:
        #     EvalRotate(v, k)[i] = v[i + k]   when 0 <= i + k < n, else 0.
        # With k = j - i ranging over [-(n-1), n-1] every (i, j) pair is
        # covered exactly once, giving out[i] = Σ_j A[i][j] v[j] at one
        # multiplicative level (diagonals are summed, not chained):
        #     diag_k[i] = A[i][i + k] = M[i + k][i]   for 0 <= i + k < n.
        self.ctx.ensure_rotation_keys([k for k in range(-(n - 1), n) if k != 0])
        acc: Any = None
        for k in range(-(n - 1), n):
            diag = np.zeros(n, dtype=float)
            for i in range(n):
                j = i + k
                if 0 <= j < n:
                    diag[i] = m[j, i]
            if not np.any(diag):
                continue
            rot = self.ciphertext if k == 0 else self.ctx.cc.EvalRotate(self.ciphertext, k)
            term = self.ctx.cc.EvalMult(rot, self.ctx.plaintext(diag.tolist()))
            acc = term if acc is None else self.ctx.cc.EvalAdd(acc, term)
        if acc is None:
            # All-zero matrix: return an encryption of zeros at the new level.
            acc = self.ctx.cc.EvalMult(self.ciphertext, 0.0)
        return self._wrap(acc, depth=self.depth + 1, n=cols)


def sign_poly_d3(x: OpenFHESlotVec) -> OpenFHESlotVec:
    """Degree-3 sign polynomial ``1.5x − 0.5x³`` (OpenFHE backend)."""
    x_sq = x.mul_ct(x)
    x_cube = x_sq.mul_ct(x)
    return x.mul_scalar(1.5) + x_cube.mul_scalar(-0.5)


def register() -> None:
    """Register the OpenFHE backend with the backend registry."""
    from .backends import FHEBackend, register_backend

    register_backend(
        FHEBackend(
            name="openfhe-ckks",
            description="OpenFHE CKKS (install the `openfhe` Python package). EXPERIMENTAL.",
            available=_HAVE_OPENFHE,
            _build_context=build_d6_context,
            _slotvec_cls=lambda: OpenFHESlotVec,
            _sign_poly=lambda: sign_poly_d3,
            experimental=True,
        )
    )
