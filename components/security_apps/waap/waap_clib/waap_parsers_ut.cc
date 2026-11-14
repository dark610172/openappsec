// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "KeyStack.h"
#include "ParserJson.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

namespace
{

class RecordingReceiver : public IParserReceiver
{
public:
    int
    onKv(const char *key, size_t key_length, const char *, size_t, int, size_t) override
    {
        keys.emplace_back(key, key_length);
        value_depths.push_back(parser->depth());
        return recordDepth();
    }

    // Deliberately omit override so these regression tests also compile against
    // the original receiver interface, where container notifications are absent.
    int
    onContainerStart()
    {
        ++container_starts;
        return recordDepth();
    }

    int
    recordDepth()
    {
        max_depth = std::max(max_depth, parser->depth());
        exceeded = max_depth > limit;
        return exceeded ? 1 : 0;
    }

    ParserBase *parser = nullptr;
    size_t limit = std::numeric_limits<size_t>::max();
    size_t max_depth = 0;
    size_t container_starts = 0;
    bool exceeded = false;
    std::vector<std::string> keys;
    std::vector<size_t> value_depths;
};

// Test every two-chunk boundary without passing an empty chunk (which means EOF).
void
expectDepth(const std::string &json, size_t expected_depth, size_t limit)
{
    for (size_t split = 0; split <= json.size(); ++split) {
        SCOPED_TRACE(json + " split=" + std::to_string(split) + " limit=" + std::to_string(limit));
        RecordingReceiver receiver;
        receiver.limit = limit;
        BufferedParser<ParserJson> parser(receiver, 0);
        receiver.parser = &parser;
        if (split > 0) {
            EXPECT_EQ(split, parser.push(json.data(), split));
        }
        if (split < json.size() && !parser.error()) {
            EXPECT_EQ(json.size() - split, parser.push(json.data() + split, json.size() - split));
        }
        if (!parser.error()) {
            parser.finish();
        }

        const bool should_exceed = expected_depth > limit;
        EXPECT_EQ(should_exceed, receiver.exceeded);
        EXPECT_EQ(should_exceed, parser.error());
        EXPECT_EQ(should_exceed ? limit + 1 : expected_depth, receiver.max_depth);
        if (should_exceed) {
            EXPECT_TRUE(receiver.keys.empty());
        } else {
            EXPECT_EQ(0u, parser.depth());
        }
    }
}

TEST(ParserJsonDepth, EmptyObjectsArraysAndMixedContainersRespectLimits)
{
    const std::vector<std::pair<std::string, size_t>> cases = {
        {"{}", 1},
        {"[]", 1},
        {"{\"a\":{\"b\":{\"c\":{}}}}", 4},
        {"[[[[]]]]", 4},
        {"[[[[0]]]]", 4},
        {"{\"a\":[{\"b\":[]}]}", 4},
        {"{\"a\":{\"b\":0}}", 2},
        {"{\"a\":{\"b\":{\"c\":0}}}", 3}
    };
    for (const auto &entry : cases) {
        expectDepth(entry.first, entry.second, 2);
        expectDepth(entry.first, entry.second, entry.second);
    }
    expectDepth("{}", 1, 0);
    expectDepth("[]", 1, 0);
    expectDepth("0 ", 0, 0);
}

TEST(ParserJsonDepth, DirectParserRetainsObservedMaximumAcrossByteChunksAndSiblings)
{
    RecordingReceiver receiver;
    ParserJson parser(receiver);
    receiver.parser = &parser;
    const std::string json = "{\"a\":{\"b\":{\"c\":{}}},\"next\":1}";
    for (const char &byte : json) {
        EXPECT_EQ(1u, parser.push(&byte, 1));
    }
    parser.finish();

    EXPECT_FALSE(parser.error());
    EXPECT_EQ(4u, receiver.max_depth);
    EXPECT_EQ(4u, receiver.container_starts);
    EXPECT_EQ(0u, parser.depth());
    EXPECT_EQ(std::vector<std::string>({"next"}), receiver.keys);
    EXPECT_EQ(std::vector<size_t>({1}), receiver.value_depths);
}

TEST(ParserJsonDepth, NonEmptyObjectDepthKeepsExistingSemantics)
{
    RecordingReceiver receiver;
    ParserJson parser(receiver);
    receiver.parser = &parser;
    const std::string json = "{\"a\":{\"b\":1},\"c\":2}";
    parser.push(json.data(), json.size());
    parser.finish();

    EXPECT_FALSE(parser.error());
    EXPECT_EQ(std::vector<std::string>({"a.b", "c"}), receiver.keys);
    EXPECT_EQ(std::vector<size_t>({2, 1}), receiver.value_depths);
    EXPECT_EQ(2u, receiver.max_depth);
}

TEST(KeyStackFallback, PoppingLongAndDottedKeysRestoresJson)
{
    KeyStack key("test");
    const std::string long_key(1100, 'x');
    key.push("json", 4);
    key.push("a.b", 3);
    key.push(long_key.data(), long_key.size());
    EXPECT_EQ("a.b." + long_key, key.str());
    EXPECT_EQ(key.str().size(), key.size());

    key.pop("long key");
    EXPECT_EQ("a.b", key.str());
    EXPECT_EQ(2u, key.depth());
    key.pop("dotted key");
    EXPECT_EQ("json", key.first());
    EXPECT_EQ("", key.str());
    EXPECT_EQ(0u, key.size());
    EXPECT_EQ(1u, key.depth());
    key.push("next", 4);
    EXPECT_EQ("next", key.str());
}

TEST(KeyStackFallback, EmptyKeysAndDottedRootKeepTheirBoundaries)
{
    KeyStack key("test");
    const std::string long_key(1100, 'x');
    key.push("j.son", 5);
    key.push("", 0);
    key.push("a.b", 3);
    key.push("", 0);
    key.push(long_key.data(), long_key.size());
    EXPECT_EQ("j.son", key.first());
    EXPECT_EQ(".a.b." + long_key, key.str());

    key.pop("long key");
    EXPECT_EQ(".a.b", key.str());
    key.pop("empty key");
    EXPECT_EQ(".a.b", key.str());
    key.pop("dotted key");
    EXPECT_EQ("", key.str());
    EXPECT_EQ(2u, key.depth());
    key.pop("empty key");
    EXPECT_EQ("j.son", key.first());
    EXPECT_EQ(1u, key.depth());
    key.pop("root");
    EXPECT_TRUE(key.empty());
}

TEST(KeyStackFallback, MultipleLongKeysAndClearPreserveMetadata)
{
    KeyStack key("test");
    const std::string long_key(1100, 'x');
    key.push("json", 4);
    key.push(long_key.data(), long_key.size());
    key.push("a.b", 3, false);
    key.push(long_key.data(), long_key.size());
    key.pop("second long key");
    EXPECT_EQ(long_key + ".a.b", key.str());
    key.pop("dotted key", false);
    EXPECT_EQ(long_key, key.str());
    EXPECT_EQ(2u, key.depth());
    key.clear();
    EXPECT_TRUE(key.empty());
    EXPECT_EQ(0u, key.depth());
    key.push("json", 4);
    key.push("next", 4);
    EXPECT_EQ("next", key.str());
}

TEST(ParserJsonKeys, LongDottedKeyDoesNotPolluteNextSibling)
{
    RecordingReceiver receiver;
    ParserJson parser(receiver);
    receiver.parser = &parser;
    const std::string long_key(1100, 'x');
    const std::string json = "{\"a.b\":{\"" + long_key + "\":\"ok\"},\"next\":\"value\"}";
    parser.push(json.data(), json.size());
    parser.finish();

    EXPECT_FALSE(parser.error());
    EXPECT_EQ(std::vector<std::string>({"a.b." + long_key, "next"}), receiver.keys);
}

} // namespace
