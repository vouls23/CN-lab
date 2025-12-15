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
    if (_fin_sent && _bytes_in_flight == 0) {
        return;
    }

    uint64_t current_window = _window_size == 0 ? 1 : _window_size;

    if (!_syn_sent) {
        if (current_window - _bytes_in_flight >= 1) {
            TCPSegment seg;
            seg.header().syn = true;
            seg.header().seqno = next_seqno();

            _segments_out.push(seg);
            _outstanding_segments.push_back(seg);

            _syn_sent = true;
            _next_seqno += 1;
            _bytes_in_flight += 1;

            if (_outstanding_segments.size() == 1) {
                _timer_ms = 0;
                _rto = _initial_retransmission_timeout;
            }
        }
    }

    while (true) {
        current_window = _window_size == 0 ? 1 : _window_size;
        uint64_t window_remaining = current_window > _bytes_in_flight ? current_window - _bytes_in_flight : 0;

        if (window_remaining == 0) {
            break;
        }

        uint64_t max_payload_for_window = window_remaining;

        TCPSegment seg;
        seg.header().seqno = next_seqno();

        size_t max_payload_len = min({
            max_payload_for_window,
            static_cast<uint64_t>(_stream.buffer_size()),
            static_cast<uint64_t>(TCPConfig::MAX_PAYLOAD_SIZE)
        });

        if (max_payload_len > 0) {
            seg.payload() = _stream.read(max_payload_len);
        }

        bool fin_possible = _stream.eof() && !_fin_sent;

        if (fin_possible) {
            if ((_stream.buffer_size() == 0 && (seg.length_in_sequence_space() + 1) <= window_remaining) ||
                (seg.length_in_sequence_space() == 0 && window_remaining >= 1 && _stream.eof())) {
                seg.header().fin = true;
                _fin_sent = true;
            }
        }

        size_t len_in_seq_space = seg.length_in_sequence_space();
        if (len_in_seq_space == 0 && !seg.header().syn) {
            break;
        }

        _segments_out.push(seg);
        _outstanding_segments.push_back(seg);

        _next_seqno += len_in_seq_space;
        _bytes_in_flight += len_in_seq_space;

        if (_outstanding_segments.size() == 1) {
            _timer_ms = 0;
            _rto = _initial_retransmission_timeout;
        }

        if (_fin_sent) {
            break;
        }
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
        _timer_ms = 0;

        TCPSegment oldest_segment = _outstanding_segments.front();
        _segments_out.push(oldest_segment); // 重新放入发送队列

        if (_window_size > 0) {
            _rto *= 2;
        }

        _consecutive_retransmissions++;
    }
}

void TCPSender::ack_received(const WrappingInt32 ackno, const uint16_t window_size) {
    _window_size = window_size;
    uint64_t ack_abs_seqno = unwrap(ackno, _isn, _next_seqno);
    if (ack_abs_seqno > _next_seqno) {
        return; 
    }
    if (ack_abs_seqno > _ack_abs_seqno) {
        bool new_bytes_acked = true;
        uint64_t old_ack_abs_seqno = _ack_abs_seqno;
        _ack_abs_seqno = ack_abs_seqno;
        auto it = _outstanding_segments.begin();
        while (it != _outstanding_segments.end()) {
            const TCPSegment& seg = *it;
            uint64_t seg_start_abs = unwrap(seg.header().seqno, _isn, old_ack_abs_seqno);
            uint64_t seg_end_abs = seg_start_abs + seg.length_in_sequence_space();
            if (ack_abs_seqno >= seg_end_abs) {
                size_t len = seg.length_in_sequence_space();
                _bytes_in_flight -= len;
                it = _outstanding_segments.erase(it);
            } else {
                break;
            }
        }
        if (new_bytes_acked) {
            _rto = _initial_retransmission_timeout;
            _consecutive_retransmissions = 0;
            _timer_ms = 0;
        }
    } 
    fill_window();
}

void TCPSender::send_empty_segment() {
    TCPSegment seg;
    seg.header().seqno = wrap(_ack_abs_seqno, _isn);
    _segments_out.push(seg);
}
