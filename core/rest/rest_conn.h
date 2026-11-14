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

#ifndef __REST_CONN_H__
#define __REST_CONN_H__

#include <string>
#include <map>
#include <chrono>
#include <cstddef>
#include "i_mainloop.h"
#include "i_rest_invoke.h"

class RestConn
{
public:
    RestConn(
        int _fd,
        I_MainLoop *_mainloop,
        const I_RestInvoke *_invoke,
        bool is_external = false,
        std::chrono::milliseconds inactivity_timeout = std::chrono::milliseconds(10000),
        std::chrono::milliseconds total_timeout = std::chrono::milliseconds(600000)
    );
    ~RestConn();

    void parseConn() const;

private:
    void stop() const;
    using Deadline = std::chrono::steady_clock::time_point;
    struct ReadTimeouts {
        Deadline inactivity;
        Deadline total;
    };
    int readData(char *data, size_t size, ReadTimeouts &timeouts) const;
    bool readLine(std::string &line, size_t &header_bytes, ReadTimeouts &timeouts) const;
    bool readSize(std::string &body, size_t len, ReadTimeouts &timeouts) const;
    void sendResponse(const std::string &status, const std::string &body, bool add_newline = true) const;

    int fd;
    I_MainLoop *mainloop;
    const I_RestInvoke *invoke;
    bool is_external_ip = false;
    std::chrono::milliseconds inactivity_timeout;
    std::chrono::milliseconds total_timeout;
};

#endif // __REST_CONN_H__
