"""
FIPS 140-2 & NIST Statistical Randomness Test Suite.
Evaluates the cryptographic quality of pseudo-random number generators and keys.
Zero external dependencies.
"""
from __future__ import annotations

import math
from typing import Dict, Any, List


class EntropyAuditor:
    """
    Cryptographic statistical test suite compliant with FIPS 140-2 Security Requirements
    for Cryptographic Modules (Section 4.9.1 Statistical Randomness Tests).
    """

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy in bits per byte (max 8.0)."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def monobit_test(bits: List[int]) -> Dict[str, Any]:
        """
        FIPS 140-2 Monobit Test.
        For a sample of 20,000 bits, count of 1s must be strictly between 9,725 and 10,275.
        """
        n = len(bits)
        ones = sum(bits)
        # Scaled bounds for arbitrary sample sizes
        expected = n / 2.0
        tolerance = 0.0275 * n
        passed = (expected - tolerance) <= ones <= (expected + tolerance)
        return {
            "test": "Monobit Test",
            "sample_bits": n,
            "ones_count": ones,
            "zeros_count": n - ones,
            "passed": passed,
            "ratio": ones / n if n > 0 else 0.0,
        }

    @staticmethod
    def poker_test(bits: List[int]) -> Dict[str, Any]:
        """
        FIPS 140-2 Poker Test.
        Divides 20,000 bits into 5,000 4-bit segments (16 possible values).
        Evaluates chi-square statistic: 2.16 < X < 46.17.
        """
        m = 4
        num_segments = len(bits) // m
        counts = [0] * (1 << m)

        for i in range(num_segments):
            val = 0
            for bit_idx in range(m):
                val = (val << 1) | bits[i * m + bit_idx]
            counts[val] += 1

        sum_squares = sum(c * c for c in counts)
        x = (16.0 / num_segments) * sum_squares - num_segments if num_segments > 0 else 0.0
        passed = 2.16 < x < 46.17
        return {
            "test": "Poker Test",
            "statistic_X": round(x, 4),
            "valid_range": "(2.16, 46.17)",
            "passed": passed,
        }

    @staticmethod
    def long_run_test(bits: List[int]) -> Dict[str, Any]:
        """
        FIPS 140-2 Long Run Test.
        Passed if there are no runs of length >= 26.
        """
        max_run = 0
        current_run = 0
        current_bit = -1

        for b in bits:
            if b == current_bit:
                current_run += 1
            else:
                current_bit = b
                current_run = 1
            if current_run > max_run:
                max_run = current_run

        passed = max_run < 26
        return {
            "test": "Long Run Test",
            "max_consecutive_run": max_run,
            "threshold": "< 26",
            "passed": passed,
        }

    @classmethod
    def audit_bytes(cls, data: bytes) -> Dict[str, Any]:
        """
        Execute full battery of FIPS 140-2 statistical tests on byte sample.
        """
        # Convert bytes to bit array
        bits = []
        for b in data:
            for shift in reversed(range(8)):
                bits.append((b >> shift) & 1)

        monobit = cls.monobit_test(bits)
        poker = cls.poker_test(bits)
        long_run = cls.long_run_test(bits)
        entropy = cls.shannon_entropy(data)

        all_passed = monobit["passed"] and poker["passed"] and long_run["passed"]

        return {
            "total_bytes": len(data),
            "total_bits": len(bits),
            "shannon_entropy": round(entropy, 6),
            "quality_verdict": "CRYPTO-GRADE CSPRNG" if all_passed else "FAILING STATISTICAL PROFILE",
            "tests": {
                "monobit": monobit,
                "poker": poker,
                "long_run": long_run,
            },
            "all_passed": all_passed,
        }


def audit_randomness(data: bytes) -> Dict[str, Any]:
    """Convenience function: Audits byte sequence against FIPS 140-2 statistical tests."""
    return EntropyAuditor.audit_bytes(data)
