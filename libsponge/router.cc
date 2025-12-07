#include "router.hh"

#include <iostream>
#include "ipv4_datagram.hh"
#include "ipv4_header.hh"
#include "util.hh"
#include <arpa/inet.h>

using namespace std;

// --- IP 校验和计算辅助函数 ---
// IP 头部校验和算法：将头部数据按 16 位字进行反码求和
uint16_t calculate_ip_checksum(const IPv4Header& header) {
    uint32_t sum = 0;
    
    // 1. 20字节头部，10个16位字
    
    // Word 1: ver + hlen + tos
    // hlen 和 ver 字段是 4 位，tos 是 8 位。
    sum += (header.ver << 12) | (header.hlen << 8) | (header.tos << 0);
    
    // Word 2: len (total length)
    // 注意：len, id, offset 等字段在结构体中是 uint16_t，需要假设它们存储的是主机字节序，
    // 但在进行 IP 校验和计算时，我们希望将它们视为网络字节序的 16 位字。
    // 在这个项目中，通常假设头部字段在结构体内是以主机字节序存储的。
    // 我们在这里使用 ntohs/ntohl 只是为了在主机字节序下重建网络字节序的数值。
    // 但更安全和常见做法是直接按主机字节序处理，因为我们是针对内存中的结构体进行计算。
    // 鉴于之前的实现尝试使用 ntohs，我们沿用这个模式，但移除 ptr 相关的冗余代码。
    
    // Word 2: len (total length)
    sum += ntohs(header.len); 
    
    // Word 3: id (identification)
    sum += ntohs(header.id);
    
    // Word 4: df + mf + offset (flags + fragment offset)
    uint16_t flags_and_offset = (header.df << 14) | (header.mf << 13) | header.offset;
    sum += ntohs(flags_and_offset); 
    
    // Word 5: ttl + proto
    sum += (header.ttl << 8) | (header.proto << 0);
    
    // Word 6: cksum (must be 0 for calculation) - 忽略
    
    // Word 7 & 8: src (32位地址分为两个 16 位字)
    sum += (header.src >> 16) & 0xFFFF;
    sum += header.src & 0xFFFF;
    
    // Word 9 & 10: dst (32位地址分为两个 16 位字)
    sum += (header.dst >> 16) & 0xFFFF;
    sum += header.dst & 0xFFFF;
    
    // 2. 将 32 位和折叠为 16 位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // 3. 取反码
    return ~sum;
}
// Dummy implementation of an IP router

// Given an incoming Internet datagram, the router decides
// (1) which interface to send it out on, and
// (2) what next hop address to send it to.

// For Lab 6, please replace with a real implementation that passes the
// automated checks run by `make check_lab6`.

// You will need to add private members to the class declaration in `router.hh`

template <typename... Targs>
void DUMMY_CODE(Targs &&... /* unused */) {}

//! \param[in] route_prefix The "up-to-32-bit" IPv4 address prefix to match the datagram's destination address against
//! \param[in] prefix_length For this route to be applicable, how many high-order (most-significant) bits of the route_prefix will need to match the corresponding bits of the datagram's destination address?
//! \param[in] next_hop The IP address of the next hop. Will be empty if the network is directly attached to the router (in which case, the next hop address should be the datagram's final destination).
//! \param[in] interface_num The index of the interface to send the datagram out on.
void Router::add_route(const uint32_t route_prefix,
                       const uint8_t prefix_length,
                       const optional<Address> next_hop,
                       const size_t interface_num) {
    cerr << "DEBUG: adding route " << Address::from_ipv4_numeric(route_prefix).ip() << "/" << int(prefix_length)
         << " => " << (next_hop.has_value() ? next_hop->ip() : "(direct)") << " on interface " << interface_num << "\n";

    // 将路由表项存入私有成员 _routing_table
    _routing_table.push_back({
        route_prefix,
        prefix_length,
        next_hop,
        interface_num
    });
}

/**
 * \brief 私有成员函数：根据最长前缀匹配 (LPM) 逻辑查找数据报的最佳路由。
 * \param[in] dst_addr 数据报目的地址的原始 32 位表示。
 * \return 匹配到的最长前缀路由条目，如果没有匹配则返回 std::nullopt。
 */
optional<Router::RouteEntry> Router::find_longest_prefix_match(const uint32_t dst_addr) {
    optional<Router::RouteEntry> best_match = nullopt;
    uint8_t longest_prefix = 0;

    for (const auto& entry : _routing_table) {
        if (entry.prefix_length == 0) {
            // 匹配所有地址 (默认路由)
            if (longest_prefix == 0) {
                // 只有当最长匹配也是 0 时才更新，确保 LPM 原则
                best_match = entry;
            }
        } else if (entry.prefix_length <= 32) {
            // 计算掩码：例如 24 位前缀的掩码是 0xFFFFFF00
            // 使用 (1U << (32 - N)) - 1 可以创建 N 位掩码，然后取反
            uint32_t mask = (~0U) << (32 - entry.prefix_length);
            
            // 检查目的地址是否与路由前缀匹配
            if ((dst_addr & mask) == (entry.route_prefix & mask)) {
                // 这是一个匹配项，检查是否是更长的前缀
                if (entry.prefix_length > longest_prefix) {
                    longest_prefix = entry.prefix_length;
                    best_match = entry;
                }
            }
        }
    }
    return best_match;
}


//! \param[in] dgram The datagram to be routed
void Router::route_one_datagram(InternetDatagram &dgram) {
    // 1. TTL 检查
    if (dgram.header().ttl <= 1) {
        // TTL <= 1, 丢弃数据报
        return;
    }
    // 2. TTL 递减和校验和重新计算
    dgram.header().ttl--;
    dgram.header().cksum = 0;
    dgram.header().cksum = calculate_ip_checksum(dgram.header()); 
    // 3. 最长前缀匹配 (LPM)
    const uint32_t dst_addr = dgram.header().dst;
    // 调用私有成员函数
    optional<Router::RouteEntry> best_route = find_longest_prefix_match(dst_addr);
    if (best_route.has_value()) {
        const auto& route = best_route.value();
        // 确定下一跳地址
        // 默认设置为最终目的地址
        Address next_hop_addr = Address::from_ipv4_numeric(dst_addr); 
        if (route.next_hop.has_value()) {
            // 使用路由表中指定的下一跳地址
            next_hop_addr = route.next_hop.value();
        }
        // 4. 发送数据报
        // 确保接口索引有效
        if (route.interface_num < _interfaces.size()) {
            _interfaces.at(route.interface_num).send_datagram(dgram, next_hop_addr);
        }
    }
}

void Router::route() {
    // Go through all the interfaces, and route every incoming datagram to its proper outgoing interface.
    for (auto &interface : _interfaces) {
        // 先处理所有收到的 datagrams
        auto &queue = interface.datagrams_out();
        while (not queue.empty()) {
            // 必须使用 front() 访问，然后 pop()
            route_one_datagram(queue.front()); 
            queue.pop();
        }
        
        // Tick 接口以处理 ARP 超时和重传
        interface.tick(0); // 假设 tick(0) 是安全且必要的驱动操作
    }
}