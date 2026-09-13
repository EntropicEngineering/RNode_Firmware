// Experimental CAT RP-to-RP request/reply turns; no persistent configuration.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#ifndef RNODE_GAME_TURNS
#define RNODE_GAME_TURNS 0
#endif
#if RNODE_GAME_TURNS != 0 && RNODE_GAME_TURNS != 1
#error "RNODE_GAME_TURNS must be 0 or 1"
#endif
#if RNODE_GAME_TURNS && (!RNODE_GAME_MODE || RNODE_RADIO_FLOOR)
#error "Game turns require game mode and exclude the radio-local floor"
#endif
namespace cat_game_turns {
constexpr unsigned CONTROL_BYTES=20;
constexpr uint32_t LEASE_MS=30000;
constexpr uint32_t GUARD_MS=5;
inline uint32_t u32(const uint8_t*p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
inline uint64_t u64(const uint8_t*p){return uint64_t(u32(p))|uint64_t(u32(p+4))<<32;}
inline void put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=v>>(8*i);}
inline uint32_t crc32(const uint8_t*p,size_t n){uint32_t crc=~0u;for(size_t i=0;i<n;i++){crc^=p[i];for(unsigned b=0;b<8;b++)crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u);}return ~crc;}
struct Control {
 uint8_t op=0,role=0,flags=0; uint64_t session=0; uint16_t window_ms=250;
 bool decode(const uint8_t*p,size_t n){
  if(n!=20||crc32(p,16)!=u32(p+16)||p[0]!=1||p[1]>3||p[2]>2||p[3]>3||p[14]||p[15])return false;
  Control c;c.op=p[1];c.role=p[2];c.flags=p[3];c.session=u64(p+4);c.window_ms=uint16_t(p[12])|uint16_t(p[13])<<8;
  if(!c.session||!c.role||c.window_ms<100||c.window_ms>2000)return false;
  *this=c;return true;
 }
};
struct Packet {uint8_t type;uint64_t session;uint32_t seq;};
inline bool packet(const uint8_t*p,size_t n,Packet &out){
 if(n<32||n>240||memcmp(p,"CLB1",4)||p[4]!=1||(p[5]!=1&&p[5]!=2)||unsigned(p[6]+(unsigned(p[7])<<8))!=n)return false;
 uint32_t crc=~0u;for(size_t i=0;i<n-4;i++){crc^=p[i];for(unsigned b=0;b<8;b++)crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u);}
 if(~crc!=u32(p+n-4))return false;
 out={p[5],u64(p+8),u32(p+16)};return out.session!=0;
}
struct State {
 Control config;bool active=false,waiting=false,seen=false;uint32_t since=0,sequence=0,lease=0;
 // TX, matched RX, expired turns, refused TX, queue high-water, airtime blocks,
 // longest host queue residence (ms), longest request-to-RP-reply arrival (ms).
 uint32_t stats[8]={};
 bool start(const Control&c,uint32_t now){if(active)return false;config=c;active=true;waiting=seen=false;lease=now;memset(stats,0,sizeof(stats));return true;}
 bool matches(const Control&c)const{return c.session==config.session&&c.role==config.role&&c.flags==config.flags&&c.window_ms==config.window_ms;}
 bool turns()const{return config.flags&1;}
 bool warm()const{return config.flags&2;}
 void expire(uint32_t now){if(waiting&&uint32_t(now-since)>=config.window_ms){waiting=false;++stats[2];}}
 bool expired(uint32_t now)const{return active&&uint32_t(now-lease)>=LEASE_MS;}
 bool receive(const Packet&p,uint32_t stamp,uint32_t now){
  if(!active||p.session!=config.session)return false;
  if(p.type!=(config.role==2?2:1))return false;
  if(!turns()){++stats[1];return true;}
  if(config.role==2){
   if(p.type!=2||!waiting||p.seq!=sequence||uint32_t(stamp-since)>=config.window_ms)return false;
   waiting=false;++stats[1];return true;
  }
  if(p.type!=1||uint32_t(now-stamp)>=config.window_ms)return false;
  // One grant per sequence, including after it expired or was consumed.
  if(seen&&int32_t(p.seq-sequence)<=0)return false;
  if(waiting) {
   if(uint32_t(stamp-since)<config.window_ms)return false;
   waiting=false;++stats[2];
  }
  seen=waiting=true;sequence=p.seq;since=stamp;++stats[1];return true;
 }
 bool can_send(const Packet&p,uint32_t now,uint32_t airtime_ms){
  if(!active||p.session!=config.session||p.type!=(config.role==2?1:2))return false;
  if(!turns())return true;
  expire(now);
  if(config.role==2)return !waiting&&(!seen||int32_t(p.seq-sequence)>0);
  return waiting&&p.seq==sequence&&uint32_t(now-since)+airtime_ms+GUARD_MS<config.window_ms;
 }
 void transmitted(const Packet&p,uint32_t now){
  ++stats[0];if(!turns())return;
  sequence=p.seq;seen=true;since=now;waiting=config.role==2;
 }
};
// Semtech SX126x explicit-header + CRC airtime, rounded up, including RNode byte.
inline uint32_t airtime_ms(unsigned payload,unsigned sf,unsigned bw,unsigned cr){
 if(sf<5||sf>12||!bw||cr<5||cr>8)return 0xffffffff;
 const bool ldro=(uint64_t(1u<<sf)*1000/bw)>=16;
 unsigned denominator=4*(sf>6&&ldro?sf-2:sf);
 int numerator=int(8*payload+16+20)-int(4*sf)+(sf>6?8:0);
 unsigned symbols=((unsigned(numerator>0?numerator:0)+denominator-1)/denominator)*cr+(sf<=6?12:8)+12+(sf<=6?2:0);
 uint64_t us=uint64_t(4*symbols+1)*(1u<<(sf-2))*1000000;
 return uint32_t((us+uint64_t(bw)*1000-1)/(uint64_t(bw)*1000));
}
}
