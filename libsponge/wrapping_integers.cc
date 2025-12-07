#include "wrapping_integers.hh"

// Dummy implementation of a 32-bit wrapping integer

// For Lab 2, please replace with a real implementation that passes the
// automated checks run by `make check_lab2`.

template <typename... Targs>
void DUMMY_CODE(Targs &&... /* unused */) {}

using namespace std;

//! Transform an "absolute" 64-bit sequence number (zero-indexed) into a WrappingInt32
//! \param n The input absolute 64-bit sequence number
//! \param isn The initial sequence number
WrappingInt32 wrap(uint64_t n, WrappingInt32 isn) {
    return WrappingInt32(static_cast<uint32_t>(isn.raw_value() + n));
}

//! Transform a WrappingInt32 into an "absolute" 64-bit sequence number (zero-indexed)
//! \param n The relative sequence number
//! \param isn The initial sequence number
//! \param checkpoint A recent absolute 64-bit sequence number
//! \returns the 64-bit sequence number that wraps to `n` and is closest to `checkpoint`
//!
//! \note Each of the two streams of the TCP connection has its own ISN. One stream
//! runs from the local TCPSender to the remote TCPReceiver and has one ISN,
//! and the other stream runs from the remote TCPSender to the local TCPReceiver and
//! has a different ISN.
uint64_t unwrap(WrappingInt32 n, WrappingInt32 isn, uint64_t checkpoint) {
    // M = 2^32 (序列号空间的大小)
    const uint64_t M = 1UL << 32; 
    // HALF_M_MAG = 2^31 (半个序列号空间的大小, 用于幅度比较)
    const uint64_t HALF_M_MAG = 1UL << 31; 

    // 1. 计算 32 位偏移量 (offset = (n - isn) mod 2^32)
    uint32_t offset = n.raw_value() - isn.raw_value();

    // 2. 计算 A_base：初始猜测值。它与 checkpoint 处于同一 2^32 周期。
    // ~0xFFFFFFFFUL 是 0xFFFFFFFF00000000UL，用于获取 checkpoint 的高 32 位（周期计数）。
    uint64_t A_base = (checkpoint & ~0xFFFFFFFFUL) | offset;

    // 3. 计算 D：checkpoint 相对于 A_base 的带符号距离。
    // D = checkpoint - A_base。D > 0 意味着 A_base 较小。
    // 使用 int64_t 进行带符号运算，避免溢出。
    int64_t D = static_cast<int64_t>(checkpoint) - static_cast<int64_t>(A_base);

    uint64_t A_res = A_base;

    // 4. 调整 A_res 到最接近 checkpoint 的周期。

    // 如果 D >= M/2 (包括 D = M/2 的平局情况)：
    // checkpoint 领先 A_base 超过或等于半个周期。A_base + M 更近/更优。
    if (D >= static_cast<int64_t>(HALF_M_MAG)) {
        A_res += M;
    } 
    // 如果 D < -M/2：
    // checkpoint 落后 A_base 超过半个周期。A_base - M 更近。
    else if (D < -static_cast<int64_t>(HALF_M_MAG)) {
        // 关键修复：只有当 A_base 足够大时，A_base - M 才是合理的候选。
        // 如果 A_base < M (如本例中的 0xFFFFFFFF)，执行 A_base - M 会导致下溢到 2^64-1 (错误)。
        // 只有当 A_base 至少包含一个完整周期时 (A_base >= M)，才执行减 M 的操作。
        if (A_base >= M) {
             A_res -= M;
        }
        // 否则（A_base < M），A_base 就是距离 checkpoint=0 最近的，不进行调整。
    } 
    // 否则，|D| < M/2 (或 D = -M/2)，A_res 保持 A_base，它是最接近的绝对序列号。
    
    return A_res;
}