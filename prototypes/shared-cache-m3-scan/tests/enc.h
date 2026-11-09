// AArch64 instruction encoders for building synthetic code in tests.
#ifndef ENC_H
#define ENC_H
#include <stdint.h>
static inline uint32_t e_movz(int sf, int rd, uint32_t imm, int hw) { return (sf ? 0xD2800000u : 0x52800000u) | (uint32_t)hw << 21 | imm << 5 | (uint32_t)rd; }
static inline uint32_t e_movn(int sf, int rd, uint32_t imm, int hw) { return (sf ? 0x92800000u : 0x12800000u) | (uint32_t)hw << 21 | imm << 5 | (uint32_t)rd; }
static inline uint32_t e_movk(int sf, int rd, uint32_t imm, int hw) { return (sf ? 0xF2800000u : 0x72800000u) | (uint32_t)hw << 21 | imm << 5 | (uint32_t)rd; }
static inline uint32_t e_ldr_x(int rt, int rn, uint32_t off) { return 0xF9400000u | (off / 8) << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_ldr_w(int rt, int rn, uint32_t off) { return 0xB9400000u | (off / 4) << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_ldrb(int rt, int rn, uint32_t off) { return 0x39400000u | off << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_ldrh(int rt, int rn, uint32_t off) { return 0x79400000u | (off / 2) << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_str_x(int rt, int rn, uint32_t off) { return 0xF9000000u | (off / 8) << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_ldp_x(int rt, int rt2, int rn, int off) { return 0xA9400000u | (uint32_t)((off / 8) & 0x7f) << 15 | (uint32_t)rt2 << 10 | (uint32_t)rn << 5 | (uint32_t)rt; }
static inline uint32_t e_add_imm(int rd, int rn, uint32_t imm) { return 0x91000000u | imm << 10 | (uint32_t)rn << 5 | (uint32_t)rd; }
static inline uint32_t e_mov_x(int rd, int rm) { return 0xAA0003E0u | (uint32_t)rm << 16 | (uint32_t)rd; }
static inline uint32_t e_adrp(int rd, uint64_t pc, uint64_t target)
{
    int64_t pages = (int64_t)((target >> 12) - (pc >> 12));
    return 0x90000000u | (uint32_t)(pages & 3) << 29 | (uint32_t)((pages >> 2) & 0x7FFFF) << 5 | (uint32_t)rd;
}
static inline uint32_t e_ldr_lit(int rt, uint64_t pc, uint64_t target) { return 0x58000000u | (uint32_t)(((int64_t)(target - pc) / 4) & 0x7FFFF) << 5 | (uint32_t)rt; }
static inline uint32_t e_bl(int64_t words) { return 0x94000000u | (uint32_t)(words & 0x3FFFFFF); }
static inline uint32_t e_ret(void) { return 0xD65F03C0u; }
static inline uint32_t e_svc80(void) { return 0xD4001001u; }
static inline uint32_t e_mrs_tpidrro(int rt) { return 0xD53BD060u | (uint32_t)rt; }
static inline uint32_t e_and_imm_x(int rd, int rn) { return 0x92400000u | (uint32_t)rn << 5 | (uint32_t)rd; }  // and Xd, Xn, #1
static inline uint32_t e_nop(void) { return 0xD503201Fu; }
#endif
