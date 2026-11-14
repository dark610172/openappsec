// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0

#include "WaapUnicode.h"
#include "gtest/gtest.h"

#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace
{

std::string
utf8(uint32_t code)
{
    std::string result;
    if (code <= 0x7F) {
        result += static_cast<char>(code);
    } else if (code <= 0x7FF) {
        result += static_cast<char>(0xC0 | (code >> 6));
        result += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code <= 0xFFFF) {
        result += static_cast<char>(0xE0 | (code >> 12));
        result += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        result += static_cast<char>(0x80 | (code & 0x3F));
    } else {
        result += static_cast<char>(0xF0 | (code >> 18));
        result += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        result += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        result += static_cast<char>(0x80 | (code & 0x3F));
    }
    return result;
}

std::string
escaped(uint32_t code, bool wide)
{
    std::ostringstream result;
    result << (wide ? "\\U" : "\\u") << std::hex << std::setfill('0')
        << std::setw(wide ? 8 : 4) << code;
    return result.str();
}

void
expectNormalized(void (*normalize)(std::string &), const std::string &input, const std::string &expected)
{
    std::string text = input;
    const size_t original_capacity = text.capacity();
    normalize(text);
    EXPECT_EQ(expected, text);
    EXPECT_LE(text.size(), input.size());
    EXPECT_EQ(original_capacity, text.capacity());
}

TEST(WaapUnicode, Utf8DoesNotJoinAsciiRunsIntoKeyword)
{
    // Accented Latin, Greek, CJK, supplementary plane, and a format character.
    for (uint32_t code : {0x00E9u, 0x03A3u, 0x4E2Du, 0x1F600u, 0x200Bu}) {
        SCOPED_TRACE(code);
        for (size_t split = 1; split < std::string("select").size(); ++split) {
            const std::string keyword = "select";
            const std::string input = keyword.substr(0, split) + utf8(code) + keyword.substr(split);
            const std::string expected = keyword.substr(0, split) + " " + keyword.substr(split);
            expectNormalized(filterUnicode, input, expected);
            // A second pass must retain the separator.
            expectNormalized(filterUnicode, expected, expected);
        }
    }
    expectNormalized(filterUnicode, "sel" + utf8(0x00E9) + utf8(0x4E2D) + "ect", "sel  ect");
}

TEST(WaapUnicode, EscapesDoNotJoinAsciiRunsIntoKeyword)
{
    for (uint32_t code : {0x00E9u, 0x03A3u, 0x4E2Du, 0x200Bu}) {
        SCOPED_TRACE(code);
        for (bool wide : {false, true}) {
            expectNormalized(unescapeUnicode, "sel" + escaped(code, wide) + "ect", "sel ect");
            expectNormalized(unescapeUnicode, "hello" + escaped(code, wide), "hello ");
        }
    }
    expectNormalized(unescapeUnicode, "sel\\U0001f600ect", "sel ect");
    expectNormalized(unescapeUnicode, "sel\\u00e9\\u4e2dect", "sel  ect");
}

TEST(WaapUnicode, BenignAsciiAndEmptyTextAreUnchanged)
{
    for (const std::string &text : {std::string(), std::string("Hello world 123_-.! select"),
        std::string("a\0b\t\r\n", 6)}) {
        expectNormalized(filterUnicode, text, text);
        expectNormalized(unescapeUnicode, text, text);
    }
    expectNormalized(unescapeUnicode, "a\\u0041b", "aAb");
    expectNormalized(unescapeUnicode, "a\\U00000041b", "aAb");
    expectNormalized(unescapeUnicode, "a\\u12", "a\\u12");
}

TEST(WaapUnicode, DocumentedLookalikeMappingsAreUnchanged)
{
    std::vector<std::pair<uint32_t, char>> mappings = {
        {0x2028, '\n'}, {0x2029, '\n'}, {0x2215, '/'}, {0x2216, '\\'},
        {0xEFC8, '\\'}, {0xF025, '\\'}
    };
    for (uint32_t code = 0xFF01; code <= 0xFF5E; ++code) {
        mappings.emplace_back(code, static_cast<char>('!' + code - 0xFF01));
    }
    for (const auto &mapping : mappings) {
        SCOPED_TRACE(mapping.first);
        const std::string expected = "a" + std::string(1, mapping.second) + "b";
        expectNormalized(filterUnicode, "a" + utf8(mapping.first) + "b", expected);
        expectNormalized(unescapeUnicode, "a" + escaped(mapping.first, false) + "b", expected);
        expectNormalized(unescapeUnicode, "a" + escaped(mapping.first, true) + "b", expected);
    }
    expectNormalized(filterUnicode, "s" + utf8(0xFF45) + "lect", "select");
    expectNormalized(unescapeUnicode, "s\\uff45lect", "select");
}

TEST(WaapUnicode, InvalidAndIncompleteUtf8RetainsBoundaries)
{
    for (const std::string &bytes : {std::string("\x80"), std::string("\xFF"),
        std::string("\xC3"), std::string("\xE2\x82"), std::string("\xF0\x9F\x98")}) {
        expectNormalized(filterUnicode, "sel" + bytes + "ect", "sel ect");
        expectNormalized(filterUnicode, "hello" + bytes, "hello ");
    }
    // Keep the existing lenient decoding of overlong ASCII used for evasion detection.
    expectNormalized(filterUnicode, "a\xC0\xAF" "b", "a/b");
    expectNormalized(filterUnicode, "a\xC0\xAE" "b", "a.b");
}

} // namespace
