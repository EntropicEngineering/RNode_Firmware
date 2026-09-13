// Opt-in, volatile, single-peer radio/driver timing experiment.
#pragma once
#include <stdint.h>
#include <stddef.h>
#ifndef RNODE_RADIO_FLOOR
#define RNODE_RADIO_FLOOR 0
#endif
#if RNODE_RADIO_FLOOR && !RNODE_GAME_MODE
#error "Radio floor requires the RAK game build"
#endif
namespace cat_radio_floor {
inline uint32_t get32(const uint8_t *p) { return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24; }
inline void put32(uint8_t *p, uint32_t n) { for(unsigned i=0;i<4;i++) p[i]=uint8_t(n>>(8*i)); }
inline uint16_t get16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(p[1])<<8; }
struct Config {
    uint8_t role=0, bytes=36;
    uint32_t session=0;
    uint16_t count=0, interval_ms=250, timeout_ms=2000;
    bool decode(const uint8_t *p, size_t n) {
        if(n!=16 || p[0]!=1 || p[1]>2 || p[2] || p[3] || p[15]) return false;
        Config c; c.role=p[1]; c.session=get32(p+4); c.count=get16(p+8);
        c.interval_ms=get16(p+10); c.timeout_ms=get16(p+12); c.bytes=p[14];
        if(c.role && (!c.session || !c.count || c.count>500 || c.interval_ms<20 || c.interval_ms>1000 || c.timeout_ms<100 || c.timeout_ms>5000 || (c.bytes!=16 && c.bytes!=36))) return false;
        *this=c; return true;
    }
};
inline void packet(uint8_t *p, unsigned n, uint8_t type, uint32_t session, uint32_t seq, uint32_t turn=0) {
    for(unsigned i=0;i<n;i++) p[i]=0xa5;
    p[0]=0xc7;p[1]=0x4c;p[2]=1;p[3]=type;
    put32(p+4,session);put32(p+8,seq);put32(p+12,turn);
}
inline bool valid(const uint8_t *p, size_t n, const Config &c) {
    if(n!=c.bytes || n<16 || p[0]!=0xc7 || p[1]!=0x4c || p[2]!=1 || (p[3]!=1 && p[3]!=2) || get32(p+4)!=c.session || get32(p+8)>=c.count) return false;
    for(size_t i=16;i<n;i++) if(p[i]!=0xa5) return false;
    return true;
}
struct Probe {
    uint32_t sent=0, received=0, timed_out=0, rejected=0, start=0, last_send=0;
    bool pending=false;
    bool due(uint32_t now, const Config &c) const { return !pending && sent<c.count && (!sent || uint32_t(now-last_send)>=uint32_t(c.interval_ms)*1000); }
    void begin(uint32_t now) { start=last_send=now; ++sent; pending=true; }
    bool expire(uint32_t now, const Config &c) {
        if(!pending || uint32_t(now-start)<uint32_t(c.timeout_ms)*1000) return false;
        pending=false; ++timed_out; return true;
    }
    bool accept(uint32_t seq, uint32_t now, uint32_t turn, const Config &c) {
        const uint32_t rtt=now-start;
        if(!pending || seq!=sent-1 || rtt>=uint32_t(c.timeout_ms)*1000 || turn>rtt) { ++rejected; return false; }
        pending=false; ++received; return true;
    }
    bool done(const Config &c) const { return sent==c.count && !pending; }
};
}
