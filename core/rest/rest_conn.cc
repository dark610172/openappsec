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

#include "rest_conn.h"

#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>

#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_API);

// The header budget includes the request line and all header delimiters.
static const size_t max_header_size = 64 * 1024;
static const size_t max_body_size = 16 * 1024 * 1024;

RestConn::RestConn(
    int _fd,
    I_MainLoop *_mainloop,
    const I_RestInvoke *_invoke,
    bool is_external,
    chrono::milliseconds _request_timeout
)
        :
        fd(_fd),
        mainloop(_mainloop),
        invoke(_invoke),
        is_external_ip(is_external),
        request_timeout(_request_timeout)
{}

RestConn::~RestConn()
{
}

static bool
compareStringCaseInsensitive(const string &s1, const string &s2)
{
    if (s1.size() != s2.size()) return false;

    for (size_t index = 0; index < s1.size(); ++index) {
        if (tolower(s1[index]) != tolower(s2[index])) return false;
    }

    return true;
}

static bool
parseContentLength(const string &data, size_t &len)
{
    size_t value = 0;
    if (data.empty()) return false;
    for (char ch : data) {
        if (ch < '0' || ch > '9') return false;
        size_t digit = ch - '0';
        if (value > (max_body_size - digit) / 10) return false;
        value = value * 10 + digit;
    }
    len = value;
    return true;
}

void
RestConn::parseConn() const
{
    const auto deadline = chrono::steady_clock::now() + request_timeout;
    size_t header_bytes = 0;
    string line;
    if (!readLine(line, header_bytes, deadline)) {
        stop();
        return;
    }

    stringstream os;
    os.str(line);
    string method;
    os >> method;

    if (method!="POST" && method!="GET") {
        dbgWarning(D_API) << "Unsupported REST method: " << method;
        sendResponse("405 Method Not Allowed", "Method " + method + " is not supported");
        return;
    }

    string uri;
    os >> uri;
    string identifier = uri.substr(uri.find_first_of('/') + 1);
    dbgDebug(D_API) << "Call identifier: " << identifier;

    size_t len = 0;
    map<string, string> headers;
    bool should_capture_headers = invoke->shouldCaptureHeaders(identifier);

    while (true) {
        if (!readLine(line, header_bytes, deadline)) {
            stop();
            return;
        }
        if (line.size() < 3) break;

        if (should_capture_headers) {
            size_t colon_pos = line.find(':');
            if (colon_pos == string::npos) continue;

            string head = line.substr(0, colon_pos);
            string data = line.substr(colon_pos + 1);

            size_t data_start = data.find_first_not_of(" \t\r\n");
            if (data_start != string::npos) {
                data = data.substr(data_start);
            } else {
                data = "";
            }

            size_t data_end = data.find_last_not_of(" \t\r\n");
            if (data_end != string::npos) {
                data = data.substr(0, data_end + 1);
            }

            if (!head.empty()) {
                headers[head] = data;
                dbgTrace(D_API) << "Captured header: " << head << " = " << data;
            }

            if (compareStringCaseInsensitive(head, "Content-Length")) {
                if (!parseContentLength(data, len)) {
                    stop();
                    return;
                }
            }
        } else {
            os.clear();
            os.str(line);
            string head, data;
            os >> head >> data;
            if (compareStringCaseInsensitive(head, "Content-Length:")) {
                if (!parseContentLength(data, len)) {
                    stop();
                    return;
                }
            }
        }
    }

    dbgDebug(D_API) << "Message length: " << len;

    if (method=="POST" && len==0) {
        dbgWarning(D_API) << "No length was found - could be chunked, but we still do not support that";
        sendResponse("411 Length Required", "");
        stop();
        return;
    }

    if (method=="GET" && invoke->isGetCall(identifier)) {
        return sendResponse("200 OK", invoke->invokeGet(identifier), false);
    }

    if (is_external_ip) {
        dbgWarning(D_API) << "External IP tried to POST";
        sendResponse("500 Internal Server Error", "", false);
        stop();
        return;
    }

    string content;
    if (!readSize(content, len, deadline)) {
        stop();
        return;
    }
    stringstream body;
    body.str(content);

    dbgTrace(D_API) << "Message content: " << body.str();

    if (method == "POST" && invoke->isPostCall(identifier)) {
        Maybe<string> result = invoke->invokePost(identifier, body.str());
        if (!result.ok()) {
            dbgWarning(D_API) << "Failed to invoke POST call: " << result.getErr();
            sendResponse("500 Internal Server Error", result.getErr());
            return;
        }
        sendResponse("200 OK", result.unpack());
        return;
    }

    Maybe<string> res = (method == "POST") ?
        invoke->invokeRest(identifier, body, headers) : invoke->getSchema(identifier);

    if (res.ok()) {
        sendResponse("200 OK", res.unpack());
    } else {
        sendResponse("500 Internal Server Error", res.getErr());
    }
}

void
RestConn::stop() const
{
    close(fd);
    mainloop->stop();
}

int
RestConn::readData(char *data, size_t size, Deadline deadline) const
{
    while (chrono::steady_clock::now() < deadline) {
        struct pollfd socket_poll = {fd, POLLIN, 0};
        int ready = poll(&socket_poll, 1, 0);
        if (ready < 0 && errno != EINTR) return -1;
        if (ready > 0) {
            if (!(socket_poll.revents & POLLIN)) return -1;
            // Even after poll(), a readiness race must never block this thread.
            int received = recv(fd, data, size, MSG_DONTWAIT);
            if (received >= 0) return received;
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        }
        mainloop->yield(true);
    }
    dbgWarning(D_API) << "REST request receive deadline exceeded on socket " << fd;
    return -1;
}

bool
RestConn::readLine(string &line, size_t &header_bytes, Deadline deadline) const
{
    line.clear();
    while (header_bytes < max_header_size) {
        char ch;
        if (readData(&ch, sizeof(ch), deadline) != sizeof(ch)) return false;
        ++header_bytes;
        line += ch;
        if (ch == '\n') return true;
    }
    dbgWarning(D_API) << "REST request headers exceed size limit on socket " << fd;
    return false;
}

bool
RestConn::readSize(string &body, size_t len, Deadline deadline) const
{
    body.clear();
    if (len > max_body_size) return false;
    while (body.size() < len) {
        char buffer[4096];
        int received = readData(buffer, min(sizeof(buffer), len - body.size()), deadline);
        if (received <= 0) return false;
        body.append(buffer, received);
    }
    return true;
}

void
RestConn::sendResponse(const string &status, const string &body, bool add_newline) const
{
    stringstream stream;
    stream <<
        "HTTP/1.1 " << status << "\r\n" <<
        "Content-Type: application/json\r\n" <<
        "Content-Length: " << (body.size() + (add_newline ? 2 : 0)) << "\r\n" <<
        "\r\n" <<
        body;
    if (add_newline) stream << "\r\n";


    string res = stream.str();
    while (res.size() > 0 ) {
        auto written = write(fd, res.c_str(), res.size());
        if (written < 1) {
            dbgWarning(D_API) << "Failed to write to socket " << fd;
            stop();
        }
        res = res.substr(written);
    }
}
