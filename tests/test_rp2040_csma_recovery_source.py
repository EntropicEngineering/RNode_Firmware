#!/usr/bin/env python3
"""Source-level regression for the RP2040 invalid-RSSI CSMA recovery."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for cursor in range(opening, len(source)):
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : cursor]
    raise AssertionError(f"unterminated function: {signature}")


class Rp2040CsmaRecoverySourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        firmware = (ROOT / "RNode_Firmware.ino").read_text()
        driver = (ROOT / "sx126x.cpp").read_text()
        cls.medium_free = function_body(firmware, "bool medium_free()")
        cls.sentinel = function_body(firmware, "void rp2040_radio_sentinel()")
        cls.current_rssi = function_body(driver, "int ISR_VECT sx126x::currentRssi()")

    def test_raw_zero_reaches_the_interference_gate(self) -> None:
        self.assertRegex(self.current_rssi, r"uint8_t\s+byte\s*=\s*0")
        self.assertIn("executeOpcodeRead(OP_CURRENT_RSSI_6X, &byte, 1)", self.current_rssi)
        self.assertRegex(self.current_rssi, r"rssi\s*=\s*-\(int\(byte\)\)\s*/\s*2")
        self.assertIn("interference_detected", self.medium_free)

    def test_backed_up_zero_rssi_gate_has_bounded_recovery(self) -> None:
        compact = re.sub(r"\s+", " ", self.sentinel)
        required_gate_terms = (
            "queue_height > 0",
            "!airtime_lock",
            "avoid_interference",
            "interference_detected",
            "!dcd",
            "current_rssi == 0",
            "om == 0x05",
        )
        for term in required_gate_terms:
            self.assertIn(term, compact)

        recovery = compact[compact.index("if (invalid_rssi_blocks_tx)") :]
        recovery = recovery[: recovery.index("if (dcd && om == 0x05)")]
        self.assertIn("!invalid_rssi_recovery_attempted", recovery)
        self.assertIn("invalid_rssi_gate == 2", recovery)
        self.assertIn("LoRa->clearIrqFlags(); lora_receive();", recovery)
        self.assertIn("invalid_rssi_gate >= 6", recovery)
        self.assertIn("stopRadio(); startRadio();", recovery)
        self.assertIn("invalid_rssi_recovery_attempted = true", recovery)
        self.assertIn("invalid_rssi_recovery_attempted = false", recovery)

        # Recovery must preserve queued host data and must not bypass CSMA.
        self.assertNotIn("flush_queue", recovery)
        self.assertNotIn("pop_queue", recovery)
        self.assertNotIn("hard_reset", recovery)
        self.assertNotIn("interference_detected = false", recovery)


if __name__ == "__main__":
    unittest.main()
