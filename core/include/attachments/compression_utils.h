// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

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

#ifndef __COMPRESSION_UTILS_H__
#define __COMPRESSION_UTILS_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

typedef enum CompressionUtilsDebugLevel
{
    COMPRESSION_DBG_LEVEL_TRACE,
    COMPRESSION_DBG_LEVEL_DEBUG,
    COMPRESSION_DBG_LEVEL_INFO,
    COMPRESSION_DBG_LEVEL_WARNING,
    COMPRESSION_DBG_LEVEL_ERROR,
    COMPRESSION_DBG_LEVEL_ASSERTION
} CompressionUtilsDebugLevel;

void resetCompressionDebugFunctionsToStandardError();
void setCompressionDebugFunction(const CompressionUtilsDebugLevel debug_level, void (*debug_function)(const char *));

typedef struct CompressionStream CompressionStream;

typedef enum CompressionType
{
    NO_COMPRESSION,
    GZIP,
    ZLIB,
    BROTLI,
    UNKNOWN_COMPRESSION = NO_COMPRESSION
} CompressionType;

CompressionStream * initCompressionStream();
void finiCompressionStream(CompressionStream *compression_stream);

#define DEFAULT_DECOMPRESSION_OUTPUT_LIMIT (256u * 1024u * 1024u)

// Limit total decoded bytes over the lifetime of the stream, across chunks and members.
// May lower the default limit; changing it does not reset usage or a previous limit failure.
void setDecompressionOutputLimit(CompressionStream *compression_stream, size_t output_limit);

typedef struct CompressionResult
{
    int            ok;
    uint32_t       num_output_bytes;
    unsigned char *output;
} CompressionResult;

CompressionResult
compressData(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const uint32_t uncompressed_data_size,
    const unsigned char *uncompressed_data,
    const int is_last_chunk
);

typedef enum DecompressionError
{
    DECOMPRESSION_ERROR_NONE,
    DECOMPRESSION_ERROR_FAILED,
    DECOMPRESSION_ERROR_OUTPUT_LIMIT
} DecompressionError;

typedef struct DecompressionResult
{
    // All errors, including budget exhaustion, set ok to 0 and return no output.
    int            ok;
    uint32_t       num_output_bytes;
    unsigned char *output;
    int            is_last_chunk;
    DecompressionError error;
} DecompressionResult;

DecompressionResult
decompressData(
    CompressionStream *compression_stream,
    const uint32_t compressed_data_size,
    const unsigned char *compressed_data
);

DecompressionResult
decompressDataSafe(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const uint32_t compressed_data_size,
    const unsigned char *compressed_data
);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __COMPRESSION_UTILS_H__
