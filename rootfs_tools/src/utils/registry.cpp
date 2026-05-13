#include "registry.hpp"
#include "logger.hpp"

CodecRegistry::~CodecRegistry() {
    for (auto &kv : codecs_) delete kv.second;
}

void CodecRegistry::register_codec(RootfsCodec *codec) {
    if (!codec) return;
    int fmt = static_cast<int>(codec->get_format());
    auto it = codecs_.find(fmt);
    if (it != codecs_.end()) {
        Log::warn("Codec for format %d already registered; replacing", fmt);
        delete it->second;
    }
    codecs_[fmt] = codec;
}

RootfsCodec *CodecRegistry::get(RootfsFormat format) const {
    auto it = codecs_.find(static_cast<int>(format));
    return (it != codecs_.end()) ? it->second : nullptr;
}
