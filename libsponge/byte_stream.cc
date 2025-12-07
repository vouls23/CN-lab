#include "byte_stream.hh"

#include <algorithm>
#include <stdexcept>
// Dummy implementation of a flow-controlled in-memory byte stream.

// For Lab 0, please replace with a real implementation that passes the
// automated checks run by `make check_lab0`.

// You will need to add private members to the class declaration in `byte_stream.hh`

template <typename... Targs>
void DUMMY_CODE(Targs &&... /* unused */) {}

using namespace std;

ByteStream::ByteStream(const size_t capacity) 
    : _capacity(capacity), _input_ended(false), _error(false), _bytes_written(0), _bytes_read(0) {}

size_t ByteStream::write(const string &data) {
    if(_input_ended || _error){
        return 0;
    }

    const size_t available_capacity = remaining_capacity();

    const size_t len_to_write = min(data.length(),available_capacity);

    for(size_t i = 0; i < len_to_write; ++i){
        _buffer.push_back(data[i]);
    }
    _bytes_written += len_to_write;

    return len_to_write;
}

//! \param[in] len bytes will be copied from the output side of the buffer
string ByteStream::peek_output(const size_t len) const {
    const size_t len_to_peek = min(len,_buffer.size());
    return string(_buffer.begin(),_buffer.begin() + len_to_peek);
}

//! \param[in] len bytes will be removed from the output side of the buffer
void ByteStream::pop_output(const size_t len) { 
    if(len > _buffer.size()){
        throw invalid_argument("ByteStream::pop_output(): len is greater than buffer size");
    }
    _buffer.erase(_buffer.begin(),_buffer.begin() + len);
    _bytes_read += len;
 }

//! Read (i.e., copy and then pop) the next "len" bytes of the stream
//! \param[in] len bytes will be popped and returned
//! \returns a string
std::string ByteStream::read(const size_t len) {
    const string result = peek_output(len);

    pop_output(result.length());
    return result;
}

void ByteStream::end_input() {
    _input_ended = true;
}

bool ByteStream::input_ended() const {
    return _input_ended;
}

size_t ByteStream::buffer_size() const {
    return _buffer.size();
}

bool ByteStream::buffer_empty() const {
    return _buffer.empty();
}

bool ByteStream::eof() const {
    return _input_ended && _buffer.empty();
}

size_t ByteStream::bytes_written() const {
    return _bytes_written;
}

size_t ByteStream::bytes_read() const {
    return _bytes_read;
}

size_t ByteStream::remaining_capacity() const {
    return _capacity - _buffer.size();
}
