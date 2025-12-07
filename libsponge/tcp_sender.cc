#include "tcp_sender.hh"

#include "tcp_config.hh"

#include <algorithm>
#include <iostream>
#include <random>

using namespace std;

//! \param[in] capacity the capacity of the outgoing byte stream
//! \param[in] retx_timeout the initial amount of time to wait before retransmitting the oldest outstanding segment
//! \param[in] fixed_isn the Initial Sequence Number to use, if set (otherwise uses a random ISN)
TCPSender::TCPSender(const size_t capacity, const uint16_t retx_timeout, const optional<WrappingInt32> fixed_isn)
    : _isn(fixed_isn.value_or(WrappingInt32{random_device()()}))
    , _initial_retransmission_timeout{retx_timeout}
    , _stream(capacity)
    , _rto(retx_timeout) // 确保 RTO 被初始化
    {}

uint64_t TCPSender::bytes_in_flight() const { 
    return _bytes_in_flight; 
}

unsigned int TCPSender::consecutive_retransmissions() const { 
    return _consecutive_retransmissions; 
}

void TCPSender::fill_window() {
    // 如果已经发送过 FIN 且所有在途字节被确认，则不再发送任何数据
    if (_fin_sent && _bytes_in_flight == 0) {
        return;
    }

    // 窗口的有效大小：如果窗口大小为 0，则视为 1（零窗口探测）
    uint64_t current_window = _window_size == 0 ? 1 : _window_size;

    // 1. 发送 SYN 段 (如果尚未发送)
    if (!_syn_sent) {
        // SYN 占据 1 个序列号空间
        if (current_window - _bytes_in_flight >= 1) {
            TCPSegment seg;
            seg.header().syn = true;
            seg.header().seqno = next_seqno();

            _segments_out.push(seg);
            _outstanding_segments.push_back(seg);

            _syn_sent = true;
            _next_seqno += 1;
            _bytes_in_flight += 1;

            // 首次发送数据，启动计时器
            if (_outstanding_segments.size() == 1) {
                _timer_ms = 0;
                _rto = _initial_retransmission_timeout;
            }
        }
    }

    // 2. 填充窗口，直到 FIN 发送或窗口满
    while (true) {
        // 重新计算剩余窗口空间（注意：window 为 0 时视作 1）
        current_window = _window_size == 0 ? 1 : _window_size;
        uint64_t window_remaining = current_window > _bytes_in_flight ? current_window - _bytes_in_flight : 0;

        // 退出条件 1: 窗口已满
        if (window_remaining == 0) {
            break;
        }

        // 计算最大可发 payload（先不预留 FIN 空间，后面通过判断来决定是否 piggyback FIN）
        uint64_t max_payload_for_window = window_remaining;

        TCPSegment seg;
        seg.header().seqno = next_seqno();

        // 限制到流中可读字节和 TCP 最大负载
        size_t max_payload_len = min({
            max_payload_for_window,
            static_cast<uint64_t>(_stream.buffer_size()),
            static_cast<uint64_t>(TCPConfig::MAX_PAYLOAD_SIZE)
        });

        // 读取 payload
        if (max_payload_len > 0) {
            seg.payload() = _stream.read(max_payload_len);
        }

        // 是否可能发送 FIN（流已经 EOF 且之前未发送过 FIN）
        bool fin_possible = _stream.eof() && !_fin_sent;

        // 设置 FIN：只要流 EOF 且当前 segment（包括 payload）+ FIN 不会超过接收窗口，就可以 piggyback
        // 注意：这里使用 <= 保证当 payload + FIN 恰好等于 window_remaining 时也能发送
        if (fin_possible) {
            // seg.length_in_sequence_space() 此时是当前 segment 占用的序列空间（payload + syn/fin if set）
            // 检查能否放入额外的 1 字节 FIN
            if ((_stream.buffer_size() == 0 && (seg.length_in_sequence_space() + 1) <= window_remaining) ||
                // 允许在 payload==0 的情况下单独发送 FIN（只要 window_remaining >= 1）
                (seg.length_in_sequence_space() == 0 && window_remaining >= 1 && _stream.eof())) {
                seg.header().fin = true;
                _fin_sent = true;
            }
        }

        // 最终检查：如果此 segment 的序列空间长度为 0 且没有 SYN（即没有任何作用），则停止发送
        size_t len_in_seq_space = seg.length_in_sequence_space();
        if (len_in_seq_space == 0 && !seg.header().syn) {
            break;
        }

        // 如果这个 segment 是只有 FIN（len_in_seq_space == 1）或者只有 payload（>0）或带 SYN 的，才发送
        // 这一点通过上面的判断已确保

        // 追踪并发送
        _segments_out.push(seg);
        _outstanding_segments.push_back(seg);

        // 更新状态
        _next_seqno += len_in_seq_space;
        _bytes_in_flight += len_in_seq_space;

        // 启动计时器（如果这是第一个 outstanding segment）
        if (_outstanding_segments.size() == 1) {
            _timer_ms = 0;
            _rto = _initial_retransmission_timeout;
        }

        // 如果设置了 FIN，按规范立即退出（FIN 只能发送一次）
        if (_fin_sent) {
            break;
        }

        // 防止在某些极端情况下出现死循环：
        // 如果我们读不到任何 payload（max_payload_len == 0）并且不能发送 FIN（fin_possible == false）
        // 则停止循环。这个判断一般在上面已经被 len_in_seq_space == 0 捕捉到，但这里额外保护更稳健。
        if (max_payload_len == 0 && !fin_possible) {
            break;
        }
    }
}

void TCPSender::tick(const size_t ms_since_last_tick) {
    if (_outstanding_segments.empty()) {
        return; // 没有待确认数据
    }

    _timer_ms += ms_since_last_tick;

    if (_timer_ms >= _rto) {
        // 重传计时器超时

        // 1. 重置定时器
        _timer_ms = 0;

        // 2. 重传最早的段
        TCPSegment oldest_segment = _outstanding_segments.front();
        _segments_out.push(oldest_segment); // 重新放入发送队列

        // 3. RTO 加倍 (如果远端窗口不为 0)
        if (_window_size > 0) {
            _rto *= 2;
        }

        // 4. 连续重传计数器增加
        _consecutive_retransmissions++;
    }
}

void TCPSender::ack_received(const WrappingInt32 ackno, const uint16_t window_size) {
    // 1. 更新窗口大小 (所有有效的 ACK 都应更新窗口大小)
    _window_size = window_size;

    // 2. 转换 ackno 为 64 位绝对序列号
    uint64_t ack_abs_seqno = unwrap(ackno, _isn, _next_seqno);

    // 3. 可靠性检查：ack_abs_seqno 必须 <= _next_seqno
    if (ack_abs_seqno > _next_seqno) {
        return; // 未来 ACK，不可靠，丢弃
    }
    
    // 4. 检查是否有新字节被确认
    if (ack_abs_seqno > _ack_abs_seqno) {
        bool new_bytes_acked = true;
        uint64_t old_ack_abs_seqno = _ack_abs_seqno;
        
        // 4a. 更新 _ack_abs_seqno
        _ack_abs_seqno = ack_abs_seqno;
        
        // 4b. 移除已确认段
        auto it = _outstanding_segments.begin();
        while (it != _outstanding_segments.end()) {
            const TCPSegment& seg = *it;
            // 使用 old_ack_abs_seqno 作为 checkpoint，确保 unwrap 稳定
            uint64_t seg_start_abs = unwrap(seg.header().seqno, _isn, old_ack_abs_seqno);
            uint64_t seg_end_abs = seg_start_abs + seg.length_in_sequence_space();

            // 如果 ack_abs_seqno >= seg_end_abs，则该段已被完全确认
            if (ack_abs_seqno >= seg_end_abs) {
                size_t len = seg.length_in_sequence_space();
                _bytes_in_flight -= len;
                it = _outstanding_segments.erase(it);
            } else {
                // 段未完全确认，停止检查后续段
                break;
            }
        }
        
        // 4c. 重置 RTO/计时器 (只有在确认了新数据时才执行)
        if (new_bytes_acked) {
            _rto = _initial_retransmission_timeout;
            _consecutive_retransmissions = 0;
            _timer_ms = 0;
        }
    } 
    // 注意：如果 ack_abs_seqno == _ack_abs_seqno (重复 ACK)，
    // RTO 不重置，但窗口大小已在步骤 1 中更新。

    // 5. 尝试填充窗口（窗口大小可能已变大）
    fill_window();
}

void TCPSender::send_empty_segment() {
    TCPSegment seg;
    // 空段使用下一个应该 ack 的序号作为 seqno（或者使用当前 ack_abs）
    seg.header().seqno = wrap(_ack_abs_seqno, _isn);
    _segments_out.push(seg);
}
