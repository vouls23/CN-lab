#include "tcp_receiver.hh"

#include <algorithm>
#include <iostream>

using namespace std;

void TCPReceiver::segment_received(const TCPSegment &seg) {
    const TCPHeader &header = seg.header();
    if (!_syn_received) {
        if (header.syn) {
            _isn = header.seqno;
            _syn_received = true;
        } else {
            return; // 丢弃非 SYN segment
        }
    }
    uint64_t abs_ackno = stream_out().bytes_written() + 1;
    if (stream_out().input_ended()) {
        abs_ackno++;
    }
    uint64_t abs_seqno = unwrap(header.seqno, _isn.value(), abs_ackno);
    
    size_t stream_index = abs_seqno + header.syn - 1;

    uint64_t window_sz = window_size();
    uint64_t win_end = abs_ackno + window_sz;
    uint64_t seg_len = seg.length_in_sequence_space();
    
    if (abs_seqno >= win_end) {
        return; 
    }
    if (seg_len == 0 && !header.syn && !header.fin) {
        return;
    }
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