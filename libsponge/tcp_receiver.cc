#include "tcp_receiver.hh"

#include <algorithm>
#include <iostream>

using namespace std;

void TCPReceiver::segment_received(const TCPSegment &seg) {
    const TCPHeader &header = seg.header();

    // 1. 处理初始 SYN (Listen 状态)
    if (!_syn_received) {
        if (header.syn) {
            _isn = header.seqno;
            _syn_received = true;
            // 继续执行，处理这个 SYN segment 中的可能包含的负载和 FIN
        } else {
            return; // 丢弃非 SYN segment
        }
    }

    // 2. 计算检查点 (abs_ackno)
    uint64_t abs_ackno = stream_out().bytes_written() + 1;
    if (stream_out().input_ended()) {
        abs_ackno++;
    }

    // 3. 将段的 32 位序列号转换为 64 位绝对序列号
    uint64_t abs_seqno = unwrap(header.seqno, _isn.value(), abs_ackno);
    
    // 4. 计算流索引和检查窗口
    
    // 流索引：数据负载的起始绝对序列号 = abs_seqno + header.syn
    // Stream index = 绝对序列号 - SYN 的长度 (1)
    size_t stream_index = abs_seqno + header.syn - 1;

    // 检查是否完全在窗口之外
    uint64_t window_sz = window_size();
    uint64_t win_end = abs_ackno + window_sz;
    uint64_t seg_len = seg.length_in_sequence_space();
    
    // 整个段在窗口之外
    if (abs_seqno >= win_end) {
        return; 
    }
    
    // 零长度且无 SYN/FIN 的段，直接丢弃
    if (seg_len == 0 && !header.syn && !header.fin) {
        return;
    }

    // 5. 推送有效载荷和 FIN 标志
    // StreamReassembler::push_substring 会自动处理 FIN 标记、裁剪窗口外的部分和数据重叠。
    _reassembler.push_substring(seg.payload().copy(), stream_index, header.fin);
}

optional<WrappingInt32> TCPReceiver::ackno() const {
    if (!_syn_received) {
        return nullopt;
    }

    uint64_t bytes_written = stream_out().bytes_written();
    uint64_t abs_ackno = bytes_written + 1;
    
    if (stream_out().input_ended()) {
        abs_ackno++;
    }

    return wrap(abs_ackno, _isn.value());
}

size_t TCPReceiver::window_size() const {
    // 窗口大小 = 总容量 - 已交付 ByteStream 但未被读取的字节数。
    size_t data_in_buffer = stream_out().buffer_size();
    
    if (_capacity > data_in_buffer) {
        return _capacity - data_in_buffer;
    }
    
    return 0;
}