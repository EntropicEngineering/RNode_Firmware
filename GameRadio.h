// Experimental CAT point-to-point radio profile. No persistent configuration.
#pragma once
#ifndef RNODE_GAME_MODE
#define RNODE_GAME_MODE 0
#endif
#if RNODE_GAME_MODE != 0 && RNODE_GAME_MODE != 1
#error "RNODE_GAME_MODE must be 0 or 1"
#endif
// SX1262 recommends >=12 preamble symbols at SF5/SF6; use 8 at SF7+.
// Integer ceiling avoids truncating the 12-symbol carrier-observation slot.
namespace cat_game_radio {
constexpr unsigned preamble(unsigned sf) { return sf <= 6 ? 12 : 8; }
constexpr unsigned slot_ms(unsigned sf, unsigned bw) {
    if (sf < 5 || sf > 12 || bw == 0) return 100;
    const unsigned duration = ((1u << sf) * 12000u + bw - 1u) / bw;
    return duration < 2 ? 2 : (duration > 100 ? 100 : duration);
}
constexpr unsigned cw_windows = 4;
}
