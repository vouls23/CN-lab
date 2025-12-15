#include "tcp_connection.hh"

#include <iostream>

// Dummy implementation of a TCP connection

// For Lab 4, please replace with a real implementation that passes the
// automated checks run by `make check`.

template <typename... Targs>
void DUMMY_CODE(Targs &&... /* unused */) {}

using namespace std;

// Helper function: 检查 _sender 的输出队列，为其中的每个数据段填充 ACK 和窗口信息，并将其移至 _segments_out 队列。
void TCPConnection::send_segments_from_sender() {
    // 2. 在发送当前数据包之前，TCPConnection 会获取当前它自己的 TCPReceiver 的 ackno 和 window size，
    //    将其放置到待发送 TCPSegment 中（设置window_size和ackno），并设置其 ACK 标志。
    while (!_sender.segments_out().empty()) {
        TCPSegment seg = _sender.segments_out().front();
        _sender.segments_out().pop();

        // 填充 ACK 和窗口大小
        if (_receiver.ackno().has_value()) {
            seg.header().ack = true;
            seg.header().ackno = _receiver.ackno().value();
            // 窗口大小不能超过 2^16 - 1
            seg.header().win = min(static_cast<size_t>(UINT16_MAX), _receiver.window_size());
        }

        _segments_out.push(seg);
    }
}

// Helper function: 发送 RST 数据段并终止连接
void TCPConnection::send_rst_and_die() {
    if (_is_active) {
        // 清空发送方的队列，防止发送旧数据
        while (!_sender.segments_out().empty()) {
            _sender.segments_out().pop();
        }
        
        // 让发送方生成一个带有有效 seqno 的空数据段
        _sender.send_empty_segment();
        
        // 取出数据段并设置 RST 标志
        TCPSegment rst_seg;
        if (!_sender.segments_out().empty()) {
            rst_seg = _sender.segments_out().front();
            _sender.segments_out().pop();
            
            // 填充 ACK 和窗口大小 (RST 包也应携带这些信息)
            if (_receiver.ackno().has_value()) {
                rst_seg.header().ack = true;
                rst_seg.header().ackno = _receiver.ackno().value();
                rst_seg.header().win = min(static_cast<size_t>(UINT16_MAX), _receiver.window_size());
            }
        } else {
            // 如果 _sender 尚未初始化 (例如在 CLOSED 状态)，则手动创建一个 RST 包。
            // 此时没有有效的 seqno/ackno，但 RST 应该被发送。
        }
        
        rst_seg.header().rst = true;
        _segments_out.push(rst_seg);

        // 将入站流和出站流都设置为错误状态，并永久终止连接。
        _receiver.stream_out().set_error();
        _sender.stream_in().set_error();
        _is_active = false;
    }
}

// Helper function: 检查是否满足优雅关闭的条件
void TCPConnection::check_for_shutdown() {
    // 优雅关闭条件:
    // 1. 入站流已经全部接收完毕。
    // 2. 出站流已经全部发送完毕。
    // 3. 需要发送的数据对方已完全确认。
    if (_receiver.stream_out().input_ended() && 
        _sender.stream_in().input_ended() && 
        _sender.bytes_in_flight() == 0) {
        
        // 如果 _linger_after_streams_finish 为 false，立即结束连接。 (对应 TIME_WAIT 的特殊情况)
        if (!_linger_after_streams_finish) {
            _is_active = false;
        }
        // 如果 _linger_after_streams_finish 为 true，则在 tick 中处理 TIME_WAIT 计时。
    }
}

size_t TCPConnection::remaining_outbound_capacity() const { 
    return _sender.stream_in().remaining_capacity(); 
}

size_t TCPConnection::bytes_in_flight() const { return _sender.bytes_in_flight(); }

size_t TCPConnection::unassembled_bytes() const { return _receiver.unassembled_bytes(); }

size_t TCPConnection::time_since_last_segment_received() const { return _time_since_last_segment_received_ms; }

void TCPConnection::segment_received(const TCPSegment &seg) { 
    
    // 收到数据段，重置计时器
    _time_since_last_segment_received_ms = 0;

    // 1. 如果设置了RST标志，将入站流和出站流都设置为错误状态，并永久终止连接。
    if (seg.header().rst) {
        _receiver.stream_out().set_error();
        _sender.stream_in().set_error();
        _is_active = false;
        return;
    }
    
    // 复制段以进行状态检查 (在调用 _receiver 之前)
    TCPSegment original_seg = seg;

    // 2. 把这个段交给TCPReceiver
    _receiver.segment_received(seg);

    // 3. 如果设置了ACK标志，则告诉TCPSender它关心的传入段的字段：ackno和window_size。
    if (seg.header().ack) {
        _sender.ack_received(seg.header().ackno, seg.header().win);
    }
    
    // --- Linger after streams finish 逻辑 (被动关闭) ---
    // 如果我方流尚未结束（我方没发FIN），但对方流结束了（我方收到了FIN），则设置 linger = false。
    // 即：我方是 Passive Closer (处于 CLOSE_WAIT 状态时)
    if (!_sender.stream_in().input_ended() && _receiver.stream_out().input_ended()) {
        // 被动关闭，不逗留。
        _linger_after_streams_finish = false;
    }
    
    // --- 填充窗口和发送分段 ---
    _sender.fill_window();
    send_segments_from_sender(); // 辅助函数：为发送队列中的分段填充 ACK/Win 并移入 _segments_out

    // 4 & 5. 如果没有数据段待发送，且收到的段占用了序列空间（SYN/FIN/数据）或者接收方有有效的 ackno (需要发送一个 ACK)
    if (_sender.segments_out().empty() && (_receiver.ackno().has_value() || original_seg.length_in_sequence_space() > 0)) {
        // 发送一个空的 ACK 数据段 (用于 keep-alive 或 纯ACK 响应)
        _sender.send_empty_segment();
        send_segments_from_sender();
    }
    
    // 检查是否可以优雅关闭
    check_for_shutdown();
}

bool TCPConnection::active() const { 
    if(!_is_active)
        return false;

    if (_receiver.stream_out().input_ended() && 
        _sender.stream_in().input_ended() && 
        _sender.bytes_in_flight() == 0) {
        
        // 如果处于 TIME_WAIT 状态（_linger_after_streams_finish 为 true），则 active 只有在超时后才变为 false
        if (_linger_after_streams_finish) {
            // 在 tick 中处理超时，这里只需要返回 _is_active
            return true;
        } else {
            // 如果不需要逗留，则在 check_for_shutdown 中 _is_active 已经被设置为 false
            return false;
        }
    }
    
    return true;
}

size_t TCPConnection::write(const string &data) {
    // 写入数据到发送方的入站流
    size_t written = _sender.stream_in().write(data);
    
    // 尝试发送数据
    _sender.fill_window();
    send_segments_from_sender();
    
    // 检查是否可以优雅关闭
    check_for_shutdown();

    return written;
}

//! \param[in] ms_since_last_tick number of milliseconds since the last call to this method
void TCPConnection::tick(const size_t ms_since_last_tick) {
    // 1. 告诉TCPSender时间的流逝。
    _sender.tick(ms_since_last_tick);

    // 2. 如果连续重传的次数超过上限TCPConfig::MAX_RETX_ATTEMPTS，则终止连接，并发送一个重置段给对端。
    if (_sender.consecutive_retransmissions() > TCPConfig::MAX_RETX_ATTEMPTS) {
        send_rst_and_die();
        return;
    }
    
    // 更新时间
    _time_since_last_segment_received_ms += ms_since_last_tick;

    // 尝试发送任何因重传而产生的段
    send_segments_from_sender();

    // 3. 如有必要，结束连接。 (Linger Timeout check)
    // 检查是否满足优雅关闭条件，且处于 TIME_WAIT (linger=true) 状态
    if (_receiver.stream_out().input_ended() && 
        _sender.stream_in().input_ended() && 
        _sender.bytes_in_flight() == 0 &&
        _linger_after_streams_finish) {
        
        // d.i: 需要停留 10 * _cfg.rt_timeout 时间后结束
        if (_time_since_last_segment_received_ms >= 10 * _cfg.rt_timeout) {
            _is_active = false;
        }
    }
}

void TCPConnection::end_input_stream() {
    // 1. Shut down the outbound byte stream
    _sender.stream_in().end_input();
    
    // 2. 尝试发送 FIN 段
    _sender.fill_window();
    send_segments_from_sender();
    
    // 3. 检查是否可以优雅关闭
    check_for_shutdown();
}

void TCPConnection::connect() {
    // 1. Initiate a connection by sending a SYN segment
    _sender.fill_window();
    send_segments_from_sender();
    
    // 2. 检查是否可以优雅关闭
    check_for_shutdown();
}

TCPConnection::~TCPConnection() {
    try {
        if (active()) {
            cerr << "Warning: Unclean shutdown of TCPConnection\n";

            // Your code here: need to send a RST segment to the peer
            send_rst_and_die();
        }
    } catch (const exception &e) {
        std::cerr << "Exception destructing TCP FSM: " << e.what() << std::endl;
    }
}
