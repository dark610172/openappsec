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

// #define WAF2_LOGGING_ENABLE
#include "debug.h"
#include "KeyStack.h"
#include <string.h>
#include "assert.h"

USE_DEBUG_FLAG(D_WAAP);

KeyStack::KeyStack(const char* name)
    :m_name(name), m_nameDepth(0), m_total_length(0), m_using_buffer(true),
    m_str_cache_valid(false), m_first_cache_valid(false) {
    m_buffer[0] = '\0';
    m_positions.reserve(16);
    m_lengths.reserve(16);
}

void
KeyStack::push(const char *subkey, size_t subkeySize, bool countDepth)
{
    bool dot_needed = !m_positions.empty() && subkey != nullptr && subkeySize > 0;
    size_t dot_size = dot_needed ? 1 : 0;
    if (m_using_buffer && !can_fit_in_buffer(subkeySize + dot_size + 1)) {
        switch_to_fallback();
    }

    // Preserve the original key boundaries in both storage modes. Dots in a key
    // and empty keys cannot be recovered by splitting the concatenated string.
    m_positions.push_back(m_total_length + dot_size);
    m_lengths.push_back(subkeySize);
    if (m_using_buffer) {
        if (dot_needed) {
            m_buffer[m_total_length++] = '.';
        }
        if (subkeySize > 0) {
            memcpy(m_buffer + m_total_length, subkey, subkeySize);
        }
        m_total_length += subkeySize;
        m_buffer[m_total_length] = '\0';
    } else {
        if (dot_needed) {
            m_fallback_key.append(1, '.');
        }
        if (subkeySize > 0) {
            m_fallback_key.append(subkey, subkeySize);
        }
        m_total_length = m_fallback_key.size();
    }

    if (countDepth) {
        m_nameDepth++;
    }
    invalidate_cache();

    dbgTrace(D_WAAP)
        << "KeyStack("
        << m_name
        << ")::push(): '"
        << std::string(subkey, subkeySize)
        << "' => full_key='"
        << c_str()
        << "'";
}

void
KeyStack::pop(const char* log, bool countDepth)
{
    if (m_positions.empty()) {
        dbgDebug(D_WAAP)
            << "KeyStack("
            << m_name
            << ")::pop(): [ERROR] ATTEMPT TO POP FROM EMPTY KEY STACK! "
            << log;
        return;
    }

    m_positions.pop_back();
    m_lengths.pop_back();
    m_total_length = m_positions.empty() ? 0 : m_positions.back() + m_lengths.back();
    if (m_using_buffer) {
        m_buffer[m_total_length] = '\0';
    } else {
        m_fallback_key.resize(m_total_length);
        if (m_total_length + 1 < MAX_KEY_SIZE) {
            rebuild_buffer_from_fallback();
        }
    }

    if (countDepth) {
        m_nameDepth--;
    }
    invalidate_cache();

    dbgTrace(D_WAAP)
        << "KeyStack("
        << m_name
        << ")::pop(): full_key='"
        << c_str()
        << "': pop_key="
        << log
        << "'";
}

void
KeyStack::print(std::ostream &os) const
{
    os
        << "KeyStack("
        << m_name
        << ")::show(): full_key='"
        << c_str()
        << "'";
}

void
KeyStack::clear()
{
    m_positions.clear();
    m_lengths.clear();
    m_fallback_key.clear();
    m_using_buffer = true;
    m_total_length = 0;
    m_buffer[0] = '\0';
    m_nameDepth = 0;
    invalidate_cache();
}

size_t
KeyStack::size() const
{
    return m_positions.size() <= 1 ? 0 : m_total_length - m_positions[1];
}

const char*
KeyStack::c_str() const
{
    if (m_positions.size() <= 1) {
        return "";
    }
    const char *data = m_using_buffer ? m_buffer : m_fallback_key.c_str();
    return data + m_positions[1];
}

const std::string
KeyStack::str() const
{
    if (!m_str_cache_valid) {
        m_cached_str.assign(c_str(), size());
        m_str_cache_valid = true;
    }
    return m_cached_str;
}

const std::string
KeyStack::first() const
{
    if (!m_first_cache_valid) {
        const char *data = m_using_buffer ? m_buffer : m_fallback_key.c_str();
        m_cached_first.assign(data, m_lengths.empty() ? 0 : m_lengths[0]);
        m_first_cache_valid = true;
    }
    return m_cached_first;
}

bool
KeyStack::can_fit_in_buffer(size_t additional_size) const
{
    return (m_total_length + additional_size) < MAX_KEY_SIZE;
}

void
KeyStack::switch_to_fallback()
{
    m_fallback_key.assign(m_buffer, m_total_length);
    m_using_buffer = false;
    invalidate_cache();
}

void
KeyStack::rebuild_buffer_from_fallback()
{
    if (m_total_length + 1 >= MAX_KEY_SIZE) {
        return;
    }

    memcpy(m_buffer, m_fallback_key.data(), m_total_length);
    m_buffer[m_total_length] = '\0';
    // Offsets and lengths already describe the exact surviving keys.
    m_fallback_key.clear();
    m_using_buffer = true;
    invalidate_cache();
}

void
KeyStack::invalidate_cache()
{
    m_str_cache_valid = false;
    m_first_cache_valid = false;
}
