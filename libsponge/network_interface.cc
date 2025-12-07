#include "network_interface.hh"

// 假设这些头文件位于 tcp_helpers/ 目录下，并且可以被 NetworkInterface 访问
#include "tcp_helpers/arp_message.hh"
#include "tcp_helpers/ethernet_frame.hh"
#include "tcp_helpers/ethernet_header.hh"
#include "tcp_helpers/ipv4_datagram.hh"
#include "util/parser.hh" // For ParseResult::NoError
#include "util/util.hh"    // For std::move

#include <iostream>
#include <vector>

using namespace std;

// 构造函数
//! \param[in] ethernet_address Ethernet (what ARP calls "hardware") address of the interface
//! \param[in] ip_address IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface(const EthernetAddress &ethernet_address, const Address &ip_address)
    : _ethernet_address(ethernet_address), _ip_address(ip_address) {
    cerr << "DEBUG: Network interface has Ethernet address " << to_string(_ethernet_address) << " and IP address "
         << ip_address.ip() << "\n";
}


// --- 辅助函数实现 ---

//! \brief 构造一个 ARP 请求帧
EthernetFrame NetworkInterface::make_arp_request(const uint32_t target_ip) const {
    // 1. 组装 ARP Message
    ARPMessage arp_request{};
    
    // **修复：使用完整的字段名称**
    arp_request.hardware_type = ARPMessage::TYPE_ETHERNET; 
    arp_request.protocol_type = EthernetHeader::TYPE_IPv4; 
    arp_request.hardware_address_size = 6;
    arp_request.protocol_address_size = 4;
    arp_request.opcode = ARPMessage::OPCODE_REQUEST;
    
    // 源信息 (本接口)
    arp_request.sender_ethernet_address = _ethernet_address;
    arp_request.sender_ip_address = _ip_address.ipv4_numeric(); 
    
    // 目标信息 (MAC 地址未知，目标 IP)
    arp_request.target_ethernet_address = {0, 0, 0, 0, 0, 0}; 
    arp_request.target_ip_address = target_ip; 

    // 2. 组装以太网帧
    EthernetFrame frame{};
    frame.header().dst = ETHERNET_BROADCAST; // 广播目标
    frame.header().src = _ethernet_address;
    frame.header().type = EthernetHeader::TYPE_ARP;
    frame.payload() = arp_request.serialize(); 
    
    return frame;
}

//! \brief 构造一个包含 IPv4 数据报的以太网帧
EthernetFrame NetworkInterface::make_ipv4_frame(const InternetDatagram &dgram, 
                                              const EthernetAddress &dst_mac) const {
    EthernetFrame frame{};
    frame.header().dst = dst_mac;
    frame.header().src = _ethernet_address;
    frame.header().type = EthernetHeader::TYPE_IPv4;
    frame.payload() = dgram.serialize(); 
    
    return frame;
}

// --- 主要方法实现 ---

//! \param[in] dgram the IPv4 datagram to be sent
//! \param[in] next_hop the IP address of the interface to send it to
void NetworkInterface::send_datagram(const InternetDatagram &dgram, const Address &next_hop) {
    const uint32_t next_hop_ip = next_hop.ipv4_numeric();

    // 1. 查 ARP 缓存表
    if (_arp_table.count(next_hop_ip)) {
        // MAC 地址已知。立即发送数据报。
        const EthernetAddress &dst_mac = _arp_table.at(next_hop_ip).mac_address;
        EthernetFrame frame = make_ipv4_frame(dgram, dst_mac);
        _frames_out.push(std::move(frame));   
    } else {
        // MAC 地址未知。
        // 1.1. 将数据报加入缓存队列
        _datagrams_waiting_for_arp[next_hop_ip].push_back(dgram);
        // 1.2. 检查是否需要发送 ARP 请求 (5秒重传逻辑)
        bool arp_request_needed = false;
        if (_arp_request_time_since_last_sent_ms.count(next_hop_ip)) {
            // 存在计时器，检查是否超时 (5s)
            if (_arp_request_time_since_last_sent_ms.at(next_hop_ip) >= ARP_REQUEST_TIMEOUT_MS) {
                arp_request_needed = true;
                _arp_request_time_since_last_sent_ms.at(next_hop_ip) = 0; // 重置计时器
            }
        } else {
            arp_request_needed = true;
            _arp_request_time_since_last_sent_ms[next_hop_ip] = 0; // 启动计时器
        }
        if (arp_request_needed) {
            EthernetFrame arp_frame = make_arp_request(next_hop_ip);
            _frames_out.push(std::move(arp_frame));
        }
    }
}

//! \param[in] frame the incoming Ethernet frame
optional<InternetDatagram> NetworkInterface::recv_frame(const EthernetFrame &frame) {
    // 1. 检查目标 MAC 地址
    const EthernetAddress &dst_mac = frame.header().dst;
    if (dst_mac != _ethernet_address && dst_mac != ETHERNET_BROADCAST) {
        return nullopt; // 不是发给我的，丢弃
    }
    // 2. 处理 ARP 消息
    if (frame.header().type == EthernetHeader::TYPE_ARP) {
        ARPMessage arp_message;
        
        if (arp_message.parse(frame.payload()) == ParseResult::NoError) {
            const uint32_t sender_ip = arp_message.sender_ip_address;
            const EthernetAddress sender_mac = arp_message.sender_ethernet_address;

            // 2.1. 存储或更新 ARP 映射 (30s 缓存)
            _arp_table[sender_ip] = {sender_mac, ARP_CACHE_LIFETIME_MS};
            
            // 2.2. 移除 ARP 请求计时器（已收到响应/请求）
            _arp_request_time_since_last_sent_ms.erase(sender_ip);

            // 2.3. 如果是 ARP 回复 (REPLY)，发送等待队列中的数据报
            if (arp_message.opcode == ARPMessage::OPCODE_REPLY) {
                if (_datagrams_waiting_for_arp.count(sender_ip)) {
                    // 依次发送所有等待的数据报
                    for (const auto &dgram : _datagrams_waiting_for_arp.at(sender_ip)) {
                        EthernetFrame ip_frame = make_ipv4_frame(dgram, sender_mac);
                        _frames_out.push(std::move(ip_frame));
                    }
                    // 清空队列
                    _datagrams_waiting_for_arp.erase(sender_ip);
                }
            }

            // 2.4. 如果是 ARP 请求 (REQUEST)，发送回复 (如果目标 IP 是本接口)
            else if (arp_message.opcode == ARPMessage::OPCODE_REQUEST) {
                if (arp_message.target_ip_address == _ip_address.ipv4_numeric()) {
                    ARPMessage arp_reply{};
                    arp_reply.hardware_type = ARPMessage::TYPE_ETHERNET;
                    arp_reply.protocol_type = EthernetHeader::TYPE_IPv4;
                    arp_reply.hardware_address_size = 6;
                    arp_reply.protocol_address_size = 4;
                    arp_reply.opcode = ARPMessage::OPCODE_REPLY; 

                    arp_reply.sender_ethernet_address = _ethernet_address;
                    arp_reply.sender_ip_address = _ip_address.ipv4_numeric();

                    arp_reply.target_ethernet_address = sender_mac; 
                    arp_reply.target_ip_address = sender_ip;

                    EthernetFrame reply_frame{};
                    reply_frame.header().dst = sender_mac; 
                    reply_frame.header().src = _ethernet_address;
                    reply_frame.header().type = EthernetHeader::TYPE_ARP;
                    reply_frame.payload() = arp_reply.serialize();

                    _frames_out.push(std::move(reply_frame));
                }
            }
        }
        
        return nullopt; // ARP 帧不返回数据报
    }
    
    // 3. 处理 IPv4 数据报
    else if (frame.header().type == EthernetHeader::TYPE_IPv4) {
        InternetDatagram dgram;
        // 确保 InternetDatagram 类名正确，否则可能需要更改为 IPv4Datagram (取决于项目定义)
        if (dgram.parse(frame.payload()) == ParseResult::NoError) {
            return dgram; // 解析成功，返回数据报
        }
    }
    // 未知类型或解析错误
    return nullopt;
}

//! \param[in] ms_since_last_tick the number of milliseconds since the last call to this method
void NetworkInterface::tick(const size_t ms_since_last_tick) {
    // 1. 检查并清除已过期的 ARP 缓存表项 (30s 缓存时间)
    for (auto it = _arp_table.begin(); it != _arp_table.end(); ) {
        ARPTableEntry &entry = it->second;
        
        if (entry.remaining_lifetime_ms > ms_since_last_tick) {
            entry.remaining_lifetime_ms -= ms_since_last_tick;
            ++it;
        } else {
            // 已过期 (剩余时间归零)
            it = _arp_table.erase(it);
        }
    }
    // 2. 检查并重传 ARP 请求 (5s 超时)
    for (auto it = _arp_request_time_since_last_sent_ms.begin(); 
         it != _arp_request_time_since_last_sent_ms.end(); 
         ++it) {
        uint32_t ip = it->first;
        size_t &time_since_last_sent = it->second;
        
        time_since_last_sent += ms_since_last_tick;
        // 检查是否达到 5s 重传阈值
        if (time_since_last_sent >= ARP_REQUEST_TIMEOUT_MS) {
            // 超时：重发 ARP 请求
            EthernetFrame arp_frame = make_arp_request(ip);
            _frames_out.push(std::move(arp_frame));
            // 重置计时器
            time_since_last_sent = 0;
        }
    }
}