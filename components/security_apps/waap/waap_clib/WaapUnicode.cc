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

#include "WaapUnicode.h"
#include "debug.h"

#include <cctype>

using namespace std;

USE_DEBUG_FLAG(D_WAAP);

namespace
{
bool isUnicodeEscapeHexDigit(char ch)
{
    return isdigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}
}

void filterUnicode(std::string & text) {
    std::string::iterator it = text.begin();
    std::string::iterator result = it;
    uint32_t acc = 0;
    int bytes_left = 0;

    for (; it != text.end(); ++it) {
        unsigned char ch = (unsigned char)(*it);

        // If character high bits are 10xxxxxx, then it might be UTF-8 character used to evade.
        // For example 0xc0, 0xaf may mean '/' in broken utf-8 decoders
        // In our implementation we do remove leading byte in UTF8 encoding (such as 0xc0),
        // but strip down the following bytes (with high bits 01).
        if (ch <= 127) {
            if (bytes_left > 0) {
                *result++ = ' '; // Preserve the boundary of an interrupted sequence.
            }
            *result++ = ch;
            bytes_left = 0; // any character <= 127 stops collecting UTF8 code
        }
        else {
            if (bytes_left == 0) {
                acc = 0;
                // collect utf8 code
                if ((ch & 0xE0) == 0xC0) { // 110X XXXX  two bytes follow

                    if ((ch & 0x1E) != 0) {
                        acc = ch & 31;
                    }
                    bytes_left = 1;
                }
                else if ((ch & 0xF0) == 0xE0) { // 1110 XXXX  three bytes follow
                    acc = ch & 15;
                    bytes_left = 2;
                }
                else if ((ch & 0xF8) == 0xF0) { // 1111 0XXX  four bytes follow
                    acc = ch & 7;
                    bytes_left = 3;
                }
                else if ((ch & 0xFC) == 0xF8) { // 1111 10XX  five bytes follow (by standard -an error)
                    acc = ch & 3;
                    bytes_left = 4;
                }
                else if ((ch & 0xFE) == 0xFC) { // 1111 110X  six bytes follow (by standard -an error)
                    acc = ch & 1;
                    bytes_left = 5;
                }
                else {
                    // Invalid leading bytes still separate adjacent ASCII runs.
                    *result++ = ' ';
                    bytes_left = 0;
                }
            }
            else if (bytes_left > 0) {
                // "good" encoder would check that the following bytes contain "10" as their high bits,
                // but buggy encoders don't, so are we!
                acc = (acc << 6) | (ch & 0x3F);
                bytes_left--;

                if (bytes_left == 0) {
                    // finished collecting the utf8 code
                    if (acc <= 127) {
                        *result++ = acc;
                    }
                    else if (isSpecialUnicode(acc)) {
                        *result++ = convertSpecialUnicode(acc);
                    }
                    else {
                        *result++ = ' '; // Preserve the boundary of an unmapped codepoint.
                    }
                    acc = 0;
                }
            }
        }
    }

    if (bytes_left > 0) {
        *result++ = ' ';
    }
    text.erase(result, text.end());
}

void unescapeUnicode(string& text) {
    string::iterator it = text.begin();
    string::iterator result = it;
    char acc[16];   // accumulates characters we are parsing and do not want to copy directly.
                    // max len really possible is "\u00000000" + 1 char = 11 chars
    char* pAcc = NULL; // when non-NULL, points where to put next character inside acc buffer
    int digitsAnticipated = 0; // in state STATE_ESCAPE, how many hex digits we anticipate to be parsed
    uint32_t code = 0; // The Unicode codepoint value can't be larger than 32 bits
    char* p;
    // in state STATE_ESCAPE_X, how many non-zerohex digits discovered - to eliminate leading zeroes like \x000012
    int nonZeroHexCounter = 0;
    enum {
        STATE_COPY,
        STATE_FLUSH,
        STATE_ESCAPE,
        STATE_ESCAPE_U,
        STATE_ESCAPE_X
    } state = STATE_COPY;

    for (; it != text.end() && result <= it; ++it) {
        const char ch = *it;

        switch (state) {
        case STATE_FLUSH: {
            // flush any accumulated left-overs into output buffer
            if (pAcc) {
                for (p = acc; p < pAcc; p++) {
                    *result++ = *p;
                }
                pAcc = NULL; // clear the acc buffer after we flushed it
            }
            state = STATE_COPY;
            // fall-through
            //RB: why no break?
        }
        // fallthrough
        case STATE_COPY: {

            if (ch == '\\') {
                // start accumulating characters instead of copying them
                pAcc = acc;
                state = STATE_ESCAPE;
                break;
            }
            break;
        }
        case STATE_ESCAPE: {
            // decide which kind of escape
            if (ch == 'u') {
                digitsAnticipated = 4; // parse/skip 4 hex digits
                code = 0;
                state = STATE_ESCAPE_U;
            }
            else if (ch == 'U') {
                digitsAnticipated = 8; // parse/skip 8 hex digits
                code = 0;
                state = STATE_ESCAPE_U;
            }
            else if (ch == 'x') {
                digitsAnticipated = 1; // anticipate at least one HEX digit after \x
                code = 0;
                nonZeroHexCounter = 0;
                state = STATE_ESCAPE_X;
            }
            else {
                // this is invalid escape sequence: rollback and copy this character too
                state = STATE_FLUSH;
            }
            break;
        }
        case STATE_ESCAPE_U: {
            if (isUnicodeEscapeHexDigit(ch)) {
                // accumulate code value
                code = (code << 4) + (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
                digitsAnticipated--;

                if (digitsAnticipated == 0) {
                    // Preserve ASCII and lookalikes; separate other Unicode codepoints.
                    if (code <= 127) {
                        *result++ = (char)code;
                    }
                    else if (isSpecialUnicode(code)) {
                        *result++ = convertSpecialUnicode(code);
                    }
                    else {
                        *result++ = ' ';
                    }

                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequencec.
                    }

                    // not STATE_COPY to avoid outputting current ch verbatim.
                    // FLUSH will output nothing because there's no ACC
                    state = STATE_FLUSH;
                    break;
                }

            }
            else {
                // invalid (non-hex) digit enountered
                state = STATE_FLUSH;
            }

            break;
        }
        case STATE_ESCAPE_X: {
            if (isUnicodeEscapeHexDigit(ch)) {
                if ((nonZeroHexCounter) > 1) {
                    *result++ = (char)code;
                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequence.
                    }
                    state = STATE_COPY;
                } else {
                    code = (code << 4) + (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
                    code &= 0xFF; // clamp the code value to two last digits
                    // Once at least one valid hex digit is here the sequence is considered
                    // valid and there's no need to accumulate it anymore.
                    if (pAcc) {
                        pAcc = NULL;
                    }

                    if (digitsAnticipated > 0) {
                        digitsAnticipated--;
                    }
                    if (code) {
                        nonZeroHexCounter++;
                    }
                }
            } else {
                // According to C standard, '\x' sequence must be followed by at least 1 valid hex digit
                if (digitsAnticipated > 0) {
                    // This is first character right after the '\x' sequence,
                    // and it is not a valid hex. This is bad sequence.
                    state = STATE_FLUSH;
                } else {
                    // We found non-hex character that terminates our \xhhhhh... sequence
                    *result++ = (char)code;
                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequence.
                    }

                    if (ch == '\\') {
                        // start accumulating characters instead of copying them
                        pAcc = acc;
                        state = STATE_ESCAPE;
                        break;
                    }

                    // STATE_COPY will cause current character (sequence terminator)
                    // to be output verbatim.
                    state = STATE_COPY;
                }
            }

            if (digitsAnticipated > 0) {
                digitsAnticipated--;
            }
            break;
        }
        }

        // Copy to output
        if (state == STATE_COPY) {
            *result++ = ch;
        }

        dbgAssertOpt(!pAcc || size_t(pAcc - acc) < sizeof(acc))
            << AlertInfo(AlertTeam::WAAP, "WAAP string unescape") <<
            "Buffer overflow detected";
        // Accumulate
        if (pAcc && size_t(pAcc - acc) < sizeof(acc)) {
            // Ensure we don't have buffer overflow
            *pAcc++ = ch;
        }
    }

    dbgTrace(D_WAAP) << " - LOOP FINISHED with state=" << state << "; digitsAnticipated=" <<
        digitsAnticipated << ", acc='" << string(acc, pAcc ? (int)(pAcc - acc) : 0) << "'";

    // Output code if we just finished decoding an escape sequence succesully and reached end of string
    if (state == STATE_ESCAPE_U && digitsAnticipated == 0 && result < text.end()) {
        // Preserve ASCII and lookalikes; separate other Unicode codepoints.
        if (code <= 127) {
            *result++ = (char)code;
        }
        else if (isSpecialUnicode(code)) {
            *result++ = convertSpecialUnicode(code);
        }
        else {
            *result++ = ' ';
        }

        if (pAcc) {
            pAcc = NULL; // throw away the accumulated source (escaped) sequencec.
        }
    }
    else if (state == STATE_ESCAPE_X) {
        if (isSpecialUnicode(code)) {
            *result++ = convertSpecialUnicode(code);
        }
        else if (digitsAnticipated == 0)
        {
            *result++ = (char)code;
        }
    }

    // flush any accumulated left-overs into output buffer
    if (pAcc) {
        for (p = acc; p < pAcc && result < text.end(); p++) {
            *result++ = *p;
        }
    }

    text.erase(result, text.end());
}

