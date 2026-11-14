#include "ParserGzip.h"
#include "cptest.h"

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{

class CountingGzipReceiver : public IParserStreamReceiver
{
public:
    int onKey(const char *, size_t) override { return 0; }
    int
    onValue(const char *, size_t size) override
    {
        bytes_received += size;
        if (throw_on_value) throw std::runtime_error("receiver failure");
        return reject_value ? 1 : 0;
    }
    int onKvDone() override { return 0; }
    int onKv(const char *, size_t, const char *, size_t, int, size_t) override { return 0; }
    void clear() override {}

    size_t bytes_received = 0;
    bool reject_value = false;
    bool throw_on_value = false;
};

std::string
compressGzip(const std::string &input)
{
    std::unique_ptr<CompressionStream, decltype(&finiCompressionStream)> stream(
        initCompressionStream(),
        &finiCompressionStream
    );
    auto result = compressData(
        stream.get(),
        CompressionType::GZIP,
        input.size(),
        reinterpret_cast<const unsigned char *>(input.data()),
        1
    );
    EXPECT_EQ(result.ok, 1);
    if (!result.ok) return "";
    std::unique_ptr<unsigned char, decltype(&std::free)> output(result.output, &std::free);
    return std::string(reinterpret_cast<char *>(output.get()), result.num_output_bytes);
}

// Run these cases under LSan to check that malloc'd decompression outputs are released.
// The receiver only counts bytes and never retains or frees the borrowed pointer.
TEST(ParserGzipTest, RepeatedSuccessfulDecompression)
{
    const size_t decoded_size = 1024 * 1024;
    const auto compressed = compressGzip(std::string(decoded_size, 'A'));
    ASSERT_FALSE(compressed.empty());
    for (int iteration = 0; iteration < 32; ++iteration) {
        CountingGzipReceiver receiver;
        ParserGzip parser(receiver, 0);
        EXPECT_EQ(parser.push(compressed.data(), compressed.size()), compressed.size());
        parser.finish();
        EXPECT_FALSE(parser.error());
        EXPECT_EQ(receiver.bytes_received, decoded_size);
    }
}

TEST(ParserGzipTest, ReceiverRejectsValue)
{
    const auto compressed = compressGzip(std::string(1024 * 1024, 'A'));
    ASSERT_FALSE(compressed.empty());
    CountingGzipReceiver receiver;
    receiver.reject_value = true;
    ParserGzip parser(receiver, 0);
    parser.push(compressed.data(), compressed.size());
    EXPECT_TRUE(parser.error());
    EXPECT_EQ(receiver.bytes_received, 1024u * 1024u);
}

TEST(ParserGzipTest, ReceiverThrowsDuringValue)
{
    const auto compressed = compressGzip(std::string(1024 * 1024, 'A'));
    ASSERT_FALSE(compressed.empty());
    CountingGzipReceiver receiver;
    receiver.throw_on_value = true;
    ParserGzip parser(receiver, 0);
    EXPECT_THROW(parser.push(compressed.data(), compressed.size()), std::runtime_error);
    EXPECT_EQ(receiver.bytes_received, 1024u * 1024u);
}

TEST(ParserGzipTest, ChunkedDecompression)
{
    const auto compressed = compressGzip(std::string(1024 * 1024, 'A'));
    ASSERT_GT(compressed.size(), 8u);
    CountingGzipReceiver receiver;
    ParserGzip parser(receiver, 0);
    // Leave the trailer for the second push, exercising the non-final output path.
    const size_t split = compressed.size() - 8;
    parser.push(compressed.data(), split);
    EXPECT_FALSE(parser.error());
    parser.push(compressed.data() + split, compressed.size() - split);
    parser.finish();
    EXPECT_FALSE(parser.error());
    EXPECT_EQ(receiver.bytes_received, 1024u * 1024u);
}

TEST(ParserGzipTest, SecondMemberInSeparatePushIsDecoded)
{
    const auto first = compressGzip("safe");
    const auto second = compressGzip("D2MARKER");
    CountingGzipReceiver receiver;
    ParserGzip parser(receiver, 0);
    EXPECT_EQ(parser.push(first.data(), first.size()), first.size());
    EXPECT_EQ(parser.push(second.data(), second.size()), second.size());
    parser.finish();
    EXPECT_FALSE(parser.error());
    EXPECT_EQ(receiver.bytes_received, 12u);
}

TEST(ParserGzipTest, GarbageAfterCompleteMemberIsAnError)
{
    const auto first = compressGzip("safe");
    CountingGzipReceiver receiver;
    ParserGzip parser(receiver, 0);
    parser.push(first.data(), first.size());
    const std::string garbage = "not a gzip member at all";
    parser.push(garbage.data(), garbage.size());
    parser.finish();
    EXPECT_TRUE(parser.error());
}

TEST(ParserGzipTest, TruncatedSecondMemberIsAnError)
{
    const auto first = compressGzip("safe");
    const auto second = compressGzip("D2MARKER");
    CountingGzipReceiver receiver;
    ParserGzip parser(receiver, 0);
    parser.push(first.data(), first.size());
    parser.push(second.data(), second.size() - 4);
    parser.finish();
    EXPECT_TRUE(parser.error());
}

}
