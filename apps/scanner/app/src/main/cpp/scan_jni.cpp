// Thin Android JNI adapter over the cross-platform AirFerry ZXing core.
// Decode policy, AF2 filtering, limits and packed layout live in one place.

#include <jni.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "airferry_zxing_core.h"

namespace {

struct PinnedY {
    JNIEnv* env;
    jbyteArray array;
    jbyte* bytes;
    size_t len;

    PinnedY(JNIEnv* e, jbyteArray a, jbyte* b, size_t n)
        : env(e), array(a), bytes(b), len(n) {}
    PinnedY(const PinnedY&) = delete;
    PinnedY& operator=(const PinnedY&) = delete;
    PinnedY(PinnedY&& other) noexcept
        : env(other.env), array(other.array), bytes(other.bytes), len(other.len)
    {
        other.bytes = nullptr;
    }
    PinnedY& operator=(PinnedY&&) = delete;

    ~PinnedY()
    {
        if (bytes != nullptr) env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    }
};

std::optional<PinnedY> PinY(
    JNIEnv* env, jbyteArray array, jint width, jint height, jint row_stride)
{
    if (array == nullptr) return std::nullopt;
    const jsize len = env->GetArrayLength(array);
    jbyte* bytes = env->GetByteArrayElements(array, nullptr);
    if (bytes == nullptr) return std::nullopt;
    if (!AirFerryZxing::ValidLuminanceGeometry(
            reinterpret_cast<const uint8_t*>(bytes), static_cast<size_t>(len),
            width, height, row_stride)) {
        env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
        return std::nullopt;
    }
    return PinnedY{env, array, bytes, static_cast<size_t>(len)};
}

jbyteArray ToJavaBytes(JNIEnv* env, const uint8_t* bytes, size_t len)
{
    if (bytes == nullptr || len == 0 || len > static_cast<size_t>(INT32_MAX)) return nullptr;
    jbyteArray out = env->NewByteArray(static_cast<jsize>(len));
    if (out == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    env->SetByteArrayRegion(
        out, 0, static_cast<jsize>(len), reinterpret_cast<const jbyte*>(bytes));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return out;
}

jbyteArray ToJavaResult(JNIEnv* env, const std::optional<AirFerryZxing::DecodeResult>& result)
{
    return result ? ToJavaBytes(env, result->payload.data(), result->payload.size()) : nullptr;
}

jbyteArray ToJavaMulti(JNIEnv* env, const std::vector<AirFerryZxing::DecodeResult>& results)
{
    const auto packed = AirFerryZxing::PackMultiResults(results);
    return ToJavaBytes(env, packed.data(), packed.size());
}

void WriteBbox(JNIEnv* env, jintArray target, const AirFerryZxing::Bbox& bbox)
{
    if (target == nullptr || env->GetArrayLength(target) < 4) return;
    const jint values[4] = {bbox[0], bbox[1], bbox[2], bbox[3]};
    env->SetIntArrayRegion(target, 0, 4, values);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

}  // namespace

extern "C" {

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeY(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height, jint row_stride)
{
    try {
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        if (!pinned) return nullptr;
        return ToJavaResult(env, AirFerryZxing::DecodeOneFull(
            reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
            width, height, row_stride));
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeYTracked(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height,
    jint row_stride, jintArray out_bbox)
{
    try {
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        if (!pinned) return nullptr;
        const auto result = AirFerryZxing::DecodeOneFull(
            reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
            width, height, row_stride);
        if (result) WriteBbox(env, out_bbox, result->bbox);
        return ToJavaResult(env, result);
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeYRegion(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height,
    jint row_stride, jint x, jint y, jint side)
{
    try {
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        if (!pinned) return nullptr;
        return ToJavaResult(env, AirFerryZxing::DecodeOneRegion(
            reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
            width, height, row_stride, x, y, side));
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeYRegionTracked(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height,
    jint row_stride, jint x, jint y, jint side, jintArray out_bbox)
{
    try {
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        if (!pinned) return nullptr;
        const auto result = AirFerryZxing::DecodeOneRegion(
            reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
            width, height, row_stride, x, y, side);
        if (result) WriteBbox(env, out_bbox, result->bbox);
        return ToJavaResult(env, result);
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeMultiY(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height, jint row_stride)
{
    try {
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        if (!pinned) return nullptr;
        return ToJavaMulti(env, AirFerryZxing::DecodeMultiFull(
            reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
            width, height, row_stride));
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_airferry_app_scan_ZxingDecoder_decodeMultiYTracked(
    JNIEnv* env, jobject, jbyteArray y_plane, jint width, jint height,
    jint row_stride, jintArray hints, jint hint_count, jfloat margin_fraction)
{
    try {
        if (hints == nullptr || hint_count <= 0 ||
            hint_count > static_cast<jint>(AirFerryZxing::MaxTrackedCodes) ||
            env->GetArrayLength(hints) < hint_count * 4) {
            return nullptr;
        }
        jint* hint_values = env->GetIntArrayElements(hints, nullptr);
        if (hint_values == nullptr) return nullptr;
        auto pinned = PinY(env, y_plane, width, height, row_stride);
        std::vector<AirFerryZxing::DecodeResult> results;
        try {
            if (pinned) {
                static_assert(sizeof(jint) == sizeof(int32_t));
                results = AirFerryZxing::DecodeMultiRegions(
                    reinterpret_cast<const uint8_t*>(pinned->bytes), pinned->len,
                    width, height, row_stride,
                    reinterpret_cast<const int32_t*>(hint_values),
                    static_cast<size_t>(hint_count), margin_fraction);
            }
        } catch (...) {
            env->ReleaseIntArrayElements(hints, hint_values, JNI_ABORT);
            return nullptr;
        }
        env->ReleaseIntArrayElements(hints, hint_values, JNI_ABORT);
        return ToJavaMulti(env, results);
    } catch (...) {
        return nullptr;
    }
}

}  // extern "C"
