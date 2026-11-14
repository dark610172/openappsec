// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef WAAP_UNICODE_H
#define WAAP_UNICODE_H

#include <cassert>
#include <cstdint>
#include <string>

// Detect whether unicode code is in the "Halfwidth and Fullwidth Forms" set convertable to ASCII.
inline bool isUnicodeHalfAndFullWidthRange(uint32_t code) {
    return (code >= 0xFF01 && code <=0xFF5E);
}

// Convert unicode code from the "Halfwidth and Fullwidth Forms" set to ASCII.
inline char convertFromUnicodeHalfAndFullWidthRange(uint32_t code) {
    assert(isUnicodeHalfAndFullWidthRange(code));
    // Support set of unicode characters from the "Halfwidth and Fullwidth Forms" that are converted to ASCII
    static const char *xlat =
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    return xlat[code - 0xFF01];
}

inline bool isSpecialUnicode(uint32_t code) {
    return isUnicodeHalfAndFullWidthRange(code)
            || 0x2028 == code || 0x2029 == code
            || 0x2215 == code || 0x2216 == code
            || 0xEFC8 == code || 0xF025 == code;
}

inline char convertSpecialUnicode(uint32_t code) {
    if (isUnicodeHalfAndFullWidthRange(code)) {
        return convertFromUnicodeHalfAndFullWidthRange(code);
    }
    else if (0x2216 == code || 0xEFC8 == code || 0xF025 == code)
    {
        return '\\';
    }
    else if (0x2215 == code)
    {
        return '/';
    }
    // assuming 0x2028 == code || 0x2029 == code
    else
    {
        return '\n';
    }
}

// Normalize in place without joining ASCII runs across unmapped Unicode.
void filterUnicode(std::string &text);
void unescapeUnicode(std::string &text);

#endif // WAAP_UNICODE_H
