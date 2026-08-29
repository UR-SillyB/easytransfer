#include "airferry_zxing_core.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

#include "BarcodeFormat.h"
#include "ImageView.h"
#include "ReadBarcode.h"

namespace AirFerryZxing {
namespace {

template <typename Bytes>
bool IsAf2Payload(const Bytes& bytes)
{
    return bytes.size() >= 30 && bytes[0] == 'A' && bytes[1] == 'F' &&
        bytes[2] == 2 && bytes[3] >= 1 && bytes[3] <= 3;
}

ZXing::ReaderOptions ReaderOptions(bool try_invert = true)
{
    ZXing::ReaderOptions options;
    options.setFormats(ZXing::BarcodeFormat::QRCode);
    options.setTryHarder(true);
    options.setTryInvert(try_invert);
    return options;
}

template <typename Position>
Bbox PositionBbox(const Position& position, int32_t offset_x = 0, int32_t offset_y = 0)
{
    Bbox bbox = {
        std::numeric_limits<int32_t>::max(),
        std::numeric_limits<int32_t>::max(),
        std::numeric_limits<int32_t>::min(),
        std::numeric_limits<int32_t>::min(),
    };
    for (size_t i = 0; i < 4; ++i) {
        const int32_t x = static_cast<int32_t>(position[i].x) + offset_x;
        const int32_t y = static_cast<int32_t>(position[i].y) + offset_y;
        bbox[0] = std::min(bbox[0], x);
        bbox[1] = std::min(bbox[1], y);
        bbox[2] = std::max(bbox[2], x);
        bbox[3] = std::max(bbox[3], y);
    }
    return bbox;
}

std::optional<DecodeResult> ToResult(
    const ZXing::Barcode& barcode,
    int32_t offset_x = 0,
    int32_t offset_y = 0)
{
    if (!barcode.isValid()) {
        return std::nullopt;
    }
    const auto& bytes = barcode.bytes();
    if (!IsAf2Payload(bytes)) {
        return std::nullopt;
    }
    return DecodeResult{
        std::vector<uint8_t>(bytes.begin(), bytes.end()),
        PositionBbox(barcode.position(), offset_x, offset_y),
    };
}

bool ValidRegion(int32_t width, int32_t height, int32_t x, int32_t y, int32_t side)
{
    if (x < 0 || y < 0 || side <= 0 || x >= width || y >= height) {
        return false;
    }
    return static_cast<int64_t>(x) + side <= width &&
        static_cast<int64_t>(y) + side <= height;
}

void AppendU32(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

}  // namespace

bool ValidLuminanceGeometry(
    const uint8_t* pixels,
    size_t pixel_len,
    int32_t width,
    int32_t height,
    int32_t row_stride) noexcept
{
    if (pixels == nullptr || width <= 0 || height <= 0 || row_stride < width) {
        return false;
    }
    const uint64_t required =
        static_cast<uint64_t>(height - 1) * static_cast<uint64_t>(row_stride) +
        static_cast<uint64_t>(width);
    return required <= pixel_len;
}

std::optional<DecodeResult> DecodeOneFull(
    const uint8_t* pixels,
    size_t pixel_len,
    int32_t width,
    int32_t height,
    int32_t row_stride)
{
    if (!ValidLuminanceGeometry(pixels, pixel_len, width, height, row_stride)) {
        return std::nullopt;
    }
    const ZXing::ImageView view(pixels, width, height, ZXing::ImageFormat::Lum, row_stride);
    return ToResult(ZXing::ReadBarcode(view, ReaderOptions()));
}

std::optional<DecodeResult> DecodeOneRegion(
    const uint8_t* pixels,
    size_t pixel_len,
    int32_t width,
    int32_t height,
    int32_t row_stride,
    int32_t x,
    int32_t y,
    int32_t side)
{
    if (!ValidLuminanceGeometry(pixels, pixel_len, width, height, row_stride) ||
        !ValidRegion(width, height, x, y, side)) {
        return std::nullopt;
    }
    const ZXing::ImageView full(pixels, width, height, ZXing::ImageFormat::Lum, row_stride);
    const ZXing::ImageView region = full.cropped(x, y, side, side);
    // Region windows are re-decodes of an already-locked code at its
    // last-known position: polarity is known (screen-projected QR is always
    // black-on-white, and a code first found non-inverted stays that way), so
    // the inverted retry only doubles the miss cost. Full-frame scans keep
    // TryInvert as the safety net for a first lock.
    return ToResult(ZXing::ReadBarcode(region, ReaderOptions(false)), x, y);
}

std::vector<DecodeResult> DecodeMultiFull(
    const uint8_t* pixels,
    size_t pixel_len,
    int32_t width,
    int32_t height,
    int32_t row_stride)
{
    std::vector<DecodeResult> decoded;
    if (!ValidLuminanceGeometry(pixels, pixel_len, width, height, row_stride)) {
        return decoded;
    }
    const ZXing::ImageView view(pixels, width, height, ZXing::ImageFormat::Lum, row_stride);
    for (const auto& barcode : ZXing::ReadBarcodes(view, ReaderOptions())) {
        if (auto result = ToResult(barcode)) {
            decoded.push_back(std::move(*result));
            if (decoded.size() == MaxTrackedCodes) {
                break;
            }
        }
    }
    return decoded;
}

std::vector<DecodeResult> DecodeMultiRegions(
    const uint8_t* pixels,
    size_t pixel_len,
    int32_t width,
    int32_t height,
    int32_t row_stride,
    const int32_t* hints,
    size_t hint_count,
    float margin_fraction)
{
    std::vector<DecodeResult> decoded;
    if (!ValidLuminanceGeometry(pixels, pixel_len, width, height, row_stride) ||
        hints == nullptr || hint_count == 0 || hint_count > MaxTrackedCodes ||
        !std::isfinite(margin_fraction)) {
        return decoded;
    }

    margin_fraction = std::clamp(margin_fraction, 0.0F, 2.0F);
    const ZXing::ImageView full(pixels, width, height, ZXing::ImageFormat::Lum, row_stride);
    // Tracked regions re-decode known codes at known positions — skip the
    // inverted retry (see DecodeOneRegion); the periodic full-frame re-lock
    // keeps TryInvert for anything exotic.
    const ZXing::ReaderOptions options = ReaderOptions(false);
    decoded.reserve(hint_count);

    for (size_t i = 0; i < hint_count; ++i) {
        const int32_t* hint = hints + i * 4;
        const int32_t min_x = std::clamp(hint[0], 0, width);
        const int32_t min_y = std::clamp(hint[1], 0, height);
        const int32_t max_x = std::clamp(hint[2], 0, width);
        const int32_t max_y = std::clamp(hint[3], 0, height);
        if (max_x <= min_x || max_y <= min_y) {
            continue;
        }

        const int32_t qr_width = max_x - min_x;
        const int32_t qr_height = max_y - min_y;
        const int32_t qr_side = std::max(qr_width, qr_height);
        const int32_t margin = static_cast<int32_t>(std::min<double>(
            qr_side,
            static_cast<double>(qr_side) * margin_fraction));
        const int32_t expanded_x0 = std::max(0, min_x - margin);
        const int32_t expanded_y0 = std::max(0, min_y - margin);
        const int32_t expanded_x1 = static_cast<int32_t>(std::min<int64_t>(
            width, static_cast<int64_t>(max_x) + margin));
        const int32_t expanded_y1 = static_cast<int32_t>(std::min<int64_t>(
            height, static_cast<int64_t>(max_y) + margin));
        const int32_t side = std::min(
            expanded_x1 - expanded_x0,
            expanded_y1 - expanded_y0);
        if (side <= 0) {
            continue;
        }

        const int32_t center_x = static_cast<int32_t>(
            (static_cast<int64_t>(expanded_x0) + expanded_x1) / 2);
        const int32_t center_y = static_cast<int32_t>(
            (static_cast<int64_t>(expanded_y0) + expanded_y1) / 2);
        const int32_t x = std::clamp(center_x - side / 2, 0, width - side);
        const int32_t y = std::clamp(center_y - side / 2, 0, height - side);
        const ZXing::ImageView region = full.cropped(x, y, side, side);
        if (auto result = ToResult(ZXing::ReadBarcode(region, options), x, y)) {
            decoded.push_back(std::move(*result));
        }
    }
    return decoded;
}

std::vector<uint8_t> PackMultiResults(const std::vector<DecodeResult>& results)
{
    if (results.empty() || results.size() > std::numeric_limits<uint32_t>::max()) {
        return {};
    }
    std::vector<uint8_t> packed;
    packed.reserve(4 + results.size() * 32);
    AppendU32(packed, static_cast<uint32_t>(results.size()));
    for (const DecodeResult& result : results) {
        if (result.payload.size() > std::numeric_limits<uint32_t>::max()) {
            return {};
        }
        AppendU32(packed, static_cast<uint32_t>(result.payload.size()));
        packed.insert(packed.end(), result.payload.begin(), result.payload.end());
        for (int32_t coordinate : result.bbox) {
            AppendU32(packed, static_cast<uint32_t>(coordinate));
        }
    }
    return packed;
}

}  // namespace AirFerryZxing
