#pragma once
#include "codecs/RootfsCodec.hpp"
#include <unordered_map>
#include <stdexcept>

class CodecRegistry {
public:
    static CodecRegistry &instance() {
        static CodecRegistry inst;
        return inst;
    }

    // Register a codec; takes ownership.
    void register_codec(RootfsCodec *codec);

    // Lookup — returns nullptr if not found.
    RootfsCodec *get(RootfsFormat format) const;

    ~CodecRegistry();

    CodecRegistry(const CodecRegistry &) = delete;
    CodecRegistry &operator=(const CodecRegistry &) = delete;

private:
    CodecRegistry() = default;
    std::unordered_map<int, RootfsCodec *> codecs_;
};
