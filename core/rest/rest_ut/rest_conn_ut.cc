// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

#include "../rest_conn.h"
#include "cptest.h"
#include "config_component.h"
#include "mainloop.h"
#include "mock/mock_environment.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace testing;

namespace {

class MockRestInvoke : public I_RestInvoke
{
public:
    using Headers = map<string, string>;
    MOCK_CONST_METHOD1(getSchema, Maybe<string>(const string &));
    MOCK_CONST_METHOD3(invokeRest, Maybe<string>(const string &, istream &, const Headers &));
    MOCK_CONST_METHOD1(isGetCall, bool(const string &));
    MOCK_CONST_METHOD1(invokeGet, string(const string &));
    MOCK_CONST_METHOD1(isPostCall, bool(const string &));
    MOCK_CONST_METHOD2(invokePost, Maybe<string>(const string &, const string &));
    MOCK_CONST_METHOD1(shouldCaptureHeaders, bool(const string &));
};

class SocketPair
{
public:
    SocketPair() { EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0); }
    ~SocketPair()
    {
        if (sockets[0] >= 0) close(sockets[0]);
        if (sockets[1] >= 0) close(sockets[1]);
    }

    int server() const { return sockets[0]; }
    int client() const { return sockets[1]; }
    void serverClosed() { sockets[0] = -1; }

    void sendRequest(const string &request)
    {
        ASSERT_EQ(
            send(client(), request.data(), request.size(), MSG_DONTWAIT | MSG_NOSIGNAL),
            static_cast<ssize_t>(request.size())
        );
    }

    string response() const
    {
        char buffer[4096];
        auto received = recv(client(), buffer, sizeof(buffer), MSG_DONTWAIT);
        EXPECT_GT(received, 0);
        return received > 0 ? string(buffer, received) : string();
    }

private:
    int sockets[2] = {-1, -1};
};

// Use the real cooperative scheduler, without RestServer startup, ports or fog setup.
// The child-process alarm also bounds regressions that block the scheduler itself.
void
checkStalledRequest(const string &request, bool has_request_line, bool keep_sending = false)
{
    NiceMock<MockEnvironment> environment;
    NiceMock<MockTimeGet> time;
    ConfigComponent config;
    MainloopComponent component;
    I_Environment::ActiveContexts contexts;
    EXPECT_CALL(environment, getActiveContexts()).WillRepeatedly(ReturnRef(contexts));
    ON_CALL(time, getMonotonicTime()).WillByDefault(Invoke([]() {
        return chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now().time_since_epoch());
    }));
    auto mainloop = Singleton::Consume<I_MainLoop>::from(component);
    StrictMock<MockRestInvoke> invoke;
    if (has_request_line) EXPECT_CALL(invoke, shouldCaptureHeaders("slow")).WillOnce(Return(false));
    EXPECT_CALL(invoke, shouldCaptureHeaders("ok")).WillOnce(Return(false));
    EXPECT_CALL(invoke, isGetCall("ok")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokeGet("ok")).WillOnce(Return("alive"));

    SocketPair stalled;
    SocketPair healthy;
    stalled.sendRequest(request);
    healthy.sendRequest("GET /ok HTTP/1.1\r\n\r\n");
    RestConn slow_conn(
        stalled.server(), mainloop, &invoke, false, chrono::milliseconds(40), chrono::milliseconds(120)
    );
    RestConn good_conn(healthy.server(), mainloop, &invoke);
    auto slow_id = mainloop->addFileRoutine(
        I_MainLoop::RoutineType::Offline,
        stalled.server(),
        [slow_conn]() { slow_conn.parseConn(); },
        "stalled REST request"
    );
    bool healthy_completed = false;
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [&]() {
            good_conn.parseConn();
            healthy_completed = true;
        },
        "complete REST request"
    );

    unsigned int heartbeats = 0;
    unsigned int heartbeats_before_close = 0;
    unsigned int heartbeats_after_close = 0;
    bool closed = false;
    unsigned int progress_bytes = 0;
    const auto start = chrono::steady_clock::now();
    auto next_input = start;
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [&]() {
            while (chrono::steady_clock::now() - start < chrono::seconds(1)) {
                ++heartbeats;
                char byte;
                auto received = recv(stalled.client(), &byte, 1, MSG_DONTWAIT);
                if (received == 0 || (received == -1 && errno == ECONNRESET)) {
                    if (!closed) {
                        closed = true;
                        stalled.serverClosed();
                        heartbeats_before_close = heartbeats - 1;
                        EXPECT_GE(
                            chrono::steady_clock::now() - start,
                            chrono::milliseconds(keep_sending ? 120 : 40)
                        );
                    }
                    if (++heartbeats_after_close == 3) break;
                } else {
                    EXPECT_EQ(received, -1);
                    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
                    if (keep_sending && chrono::steady_clock::now() >= next_input) {
                        stalled.sendRequest("x");
                        ++progress_bytes;
                        next_input = chrono::steady_clock::now() + chrono::milliseconds(5);
                    }
                }
                mainloop->yield(true);
            }
        },
        "REST test heartbeat",
        true
    );
    mainloop->run();

    EXPECT_TRUE(closed);
    EXPECT_GT(heartbeats_before_close, 1u);
    EXPECT_EQ(heartbeats_after_close, 3u);
    EXPECT_FALSE(mainloop->doesRoutineExist(slow_id));
    EXPECT_TRUE(healthy_completed);
    if (keep_sending) EXPECT_GT(progress_bytes, 3u);
    EXPECT_EQ(
        healthy.response(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nalive"
    );
    component.fini();
}

class RestConnInputTest : public Test
{
protected:
    void expectClosed()
    {
        EXPECT_CALL(mainloop, stop()).WillOnce(Invoke([this]() { sockets.serverClosed(); }));
    }

    SocketPair sockets;
    StrictMock<MockMainLoop> mainloop;
    StrictMock<MockRestInvoke> invoke;
};

TEST(RestConnDeadline, partial_request_line_yields_and_closes_only_its_connection)
{
    ASSERT_EXIT(
        {
            alarm(5);
            checkStalledRequest("GET /", false);
            _exit(Test::HasFailure() ? 1 : 0);
        },
        ExitedWithCode(0),
        ""
    );
}

TEST(RestConnDeadline, partial_headers_yield_and_expire)
{
    ASSERT_EXIT(
        {
            alarm(5);
            checkStalledRequest("POST /slow HTTP/1.1\r\nContent-Len", true);
            _exit(Test::HasFailure() ? 1 : 0);
        },
        ExitedWithCode(0),
        ""
    );
}

TEST(RestConnDeadline, partial_body_yields_and_expires)
{
    ASSERT_EXIT(
        {
            alarm(5);
            checkStalledRequest("POST /slow HTTP/1.1\r\nContent-Length: 4\r\n\r\nab", true);
            _exit(Test::HasFailure() ? 1 : 0);
        },
        ExitedWithCode(0),
        ""
    );
}

TEST(RestConnDeadline, continued_input_does_not_reset_the_total_deadline)
{
    ASSERT_EXIT(
        {
            alarm(5);
            checkStalledRequest("GET /", false, true);
            _exit(Test::HasFailure() ? 1 : 0);
        },
        ExitedWithCode(0),
        ""
    );
}

TEST(RestConnDeadline, progressing_body_still_expires_at_total_limit)
{
    ASSERT_EXIT(
        {
            alarm(5);
            checkStalledRequest("POST /slow HTTP/1.1\r\nContent-Length: 1000\r\n\r\na", true, true);
            _exit(Test::HasFailure() ? 1 : 0);
        },
        ExitedWithCode(0),
        ""
    );
}

TEST_F(RestConnInputTest, slow_progress_resets_inactivity_across_headers_and_body)
{
    const vector<string> fragments = {
        "POST /ec", "ho HTTP/1.1\r\nContent-Len", "gth: 5\r\n", "X-Test: value\r\n", "\r\nh",
        "e", "l", "l", "o"
    };
    size_t next = 1;
    sockets.sendRequest(fragments[0]);
    EXPECT_CALL(mainloop, yield(true)).Times(fragments.size() - 1).WillRepeatedly(Invoke([&]() {
        this_thread::sleep_for(chrono::milliseconds(25));
        ASSERT_LT(next, fragments.size());
        sockets.sendRequest(fragments[next++]);
    }));
    EXPECT_CALL(invoke, shouldCaptureHeaders("echo")).WillOnce(Return(true));
    EXPECT_CALL(invoke, isPostCall("echo")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokePost("echo", "hello")).WillOnce(Return(Maybe<string>(string("hello"))));
    const auto start = chrono::steady_clock::now();
    RestConn(
        sockets.server(), &mainloop, &invoke, false, chrono::milliseconds(100), chrono::milliseconds(2000)
    ).parseConn();
    EXPECT_GE(chrono::steady_clock::now() - start, chrono::milliseconds(100));
    EXPECT_EQ(next, fragments.size());
    EXPECT_THAT(sockets.response(), HasSubstr("200 OK"));
}

TEST_F(RestConnInputTest, silence_after_progress_expires_from_last_received_byte)
{
    sockets.sendRequest("POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nh");
    EXPECT_CALL(invoke, shouldCaptureHeaders("echo")).WillOnce(Return(false));
    bool progressed = false;
    chrono::steady_clock::time_point last_progress;
    EXPECT_CALL(mainloop, yield(true)).WillRepeatedly(Invoke([&]() {
        if (progressed) return;
        this_thread::sleep_for(chrono::milliseconds(25));
        sockets.sendRequest("e");
        last_progress = chrono::steady_clock::now();
        progressed = true;
    }));
    EXPECT_CALL(mainloop, stop()).WillOnce(Invoke([&]() {
        EXPECT_TRUE(progressed);
        EXPECT_GE(chrono::steady_clock::now() - last_progress, chrono::milliseconds(100));
        sockets.serverClosed();
    }));
    RestConn(
        sockets.server(), &mainloop, &invoke, false, chrono::milliseconds(100), chrono::milliseconds(2000)
    ).parseConn();
}

TEST_F(RestConnInputTest, complete_post_preserves_body_and_response)
{
    sockets.sendRequest("POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");
    EXPECT_CALL(invoke, shouldCaptureHeaders("echo")).WillOnce(Return(false));
    EXPECT_CALL(invoke, isPostCall("echo")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokePost("echo", "hello")).WillOnce(Return(Maybe<string>(string("hello"))));
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
    EXPECT_EQ(
        sockets.response(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\nhello\r\n"
    );
}

TEST_F(RestConnInputTest, fragmented_post_completes_after_yield)
{
    sockets.sendRequest("POST /ec");
    EXPECT_CALL(mainloop, yield(true)).WillOnce(Invoke([this]() {
        sockets.sendRequest("ho HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");
    }));
    EXPECT_CALL(invoke, shouldCaptureHeaders("echo")).WillOnce(Return(false));
    EXPECT_CALL(invoke, isPostCall("echo")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokePost("echo", "hello")).WillOnce(Return(Maybe<string>(string("hello"))));
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
    EXPECT_THAT(sockets.response(), HasSubstr("200 OK"));
}

TEST_F(RestConnInputTest, complete_request_preserves_captured_headers)
{
    sockets.sendRequest("POST /call HTTP/1.1\r\nX-Test: value\r\ncontent-length: 2\r\n\r\n{}");
    EXPECT_CALL(invoke, shouldCaptureHeaders("call")).WillOnce(Return(true));
    EXPECT_CALL(invoke, isPostCall("call")).WillOnce(Return(false));
    EXPECT_CALL(invoke, invokeRest("call", _, _)).WillOnce(Invoke(
        [](const string &, istream &body, const MockRestInvoke::Headers &headers) -> Maybe<string> {
            string content;
            getline(body, content);
            EXPECT_EQ(content, "{}");
            EXPECT_EQ(headers.at("X-Test"), "value");
            EXPECT_EQ(headers.at("content-length"), "2");
            return string("ok");
        }
    ));
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
    EXPECT_THAT(sockets.response(), HasSubstr("200 OK"));
}

TEST_F(RestConnInputTest, external_get_still_works)
{
    sockets.sendRequest("GET /ok HTTP/1.1\r\n\r\n");
    EXPECT_CALL(invoke, shouldCaptureHeaders("ok")).WillOnce(Return(false));
    EXPECT_CALL(invoke, isGetCall("ok")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokeGet("ok")).WillOnce(Return("ok"));
    RestConn(sockets.server(), &mainloop, &invoke, true).parseConn();
    EXPECT_THAT(sockets.response(), HasSubstr("200 OK"));
}

TEST_F(RestConnInputTest, external_post_is_rejected_before_reading_body)
{
    sockets.sendRequest("POST /call HTTP/1.1\r\nContent-Length: 2\r\n\r\n");
    EXPECT_CALL(invoke, shouldCaptureHeaders("call")).WillOnce(Return(false));
    expectClosed();
    RestConn(sockets.server(), &mainloop, &invoke, true).parseConn();
    EXPECT_EQ(
        sockets.response(),
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
    );
}

TEST_F(RestConnInputTest, oversized_request_line_is_closed)
{
    sockets.sendRequest("GET /" + string(64 * 1024, 'x'));
    expectClosed();
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
}

TEST_F(RestConnInputTest, aggregate_header_size_is_limited)
{
    string request = "GET /call HTTP/1.1\r\n";
    while (request.size() <= 64 * 1024) request += "X-Test: " + string(1000, 'x') + "\r\n";
    sockets.sendRequest(request);
    EXPECT_CALL(invoke, shouldCaptureHeaders("call")).WillOnce(Return(true));
    expectClosed();
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
}

TEST_F(RestConnInputTest, body_limit_rejects_oversized_and_overflowing_lengths)
{
    const string lengths[] = {
        to_string(static_cast<unsigned long long>(INT_MAX) + 1),
        "184467440737095516160", "-1", "-2147483649", "no-number", ""
    };
    for (bool capture_headers : {false, true}) {
        for (const string &length : lengths) {
            SocketPair connection;
            connection.sendRequest("POST /call HTTP/1.1\r\nContent-Length: " + length + "\r\n\r\n");
            EXPECT_CALL(invoke, shouldCaptureHeaders("call")).WillOnce(Return(capture_headers));
            EXPECT_CALL(mainloop, stop()).WillOnce(Invoke([&]() { connection.serverClosed(); }));
            RestConn(connection.server(), &mainloop, &invoke).parseConn();
        }
    }
}

TEST_F(RestConnInputTest, compatibility_lengths_are_accepted_before_reading_the_body)
{
    const string lengths[] = {"16777217", to_string(INT_MAX)};
    for (bool capture_headers : {false, true}) {
        for (const string &length : lengths) {
            SocketPair connection;
            connection.sendRequest("POST /call HTTP/1.1\r\nContent-Length: " + length + "\r\n\r\n");
            EXPECT_CALL(invoke, shouldCaptureHeaders("call")).WillOnce(Return(capture_headers));
            // A yield proves that the header was accepted and the body reader is waiting for data.
            EXPECT_CALL(mainloop, yield(true)).WillOnce(Invoke([&]() {
                EXPECT_EQ(shutdown(connection.client(), SHUT_WR), 0);
            }));
            EXPECT_CALL(mainloop, stop()).WillOnce(Invoke([&]() { connection.serverClosed(); }));
            RestConn(connection.server(), &mainloop, &invoke).parseConn();
        }
    }
}

TEST_F(RestConnInputTest, body_larger_than_sixteen_mib_reaches_the_handler)
{
    const size_t body_size = 16 * 1024 * 1024 + 1;
    sockets.sendRequest("POST /large HTTP/1.1\r\nContent-Length: " + to_string(body_size) + "\r\n\r\n");
    size_t sent = 0;
    EXPECT_CALL(mainloop, yield(true)).WillRepeatedly(Invoke([&]() {
        ASSERT_LT(sent, body_size);
        const string chunk(min(static_cast<size_t>(4096), body_size - sent), 'x');
        sockets.sendRequest(chunk);
        sent += chunk.size();
    }));
    EXPECT_CALL(invoke, shouldCaptureHeaders("large")).WillOnce(Return(false));
    EXPECT_CALL(invoke, isPostCall("large")).WillOnce(Return(true));
    EXPECT_CALL(invoke, invokePost("large", _)).WillOnce(Invoke(
        [&](const string &, const string &body) -> Maybe<string> {
            EXPECT_EQ(body.size(), body_size);
            EXPECT_EQ(body, string(body_size, 'x'));
            return string("ok");
        }
    ));
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
    EXPECT_EQ(sent, body_size);
    EXPECT_THAT(sockets.response(), HasSubstr("200 OK"));
}

TEST_F(RestConnInputTest, original_stoi_numeric_prefixes_remain_compatible)
{
    for (bool capture_headers : {false, true}) {
        for (const char *length : {"+5", "0005", "5suffix"}) {
            SocketPair connection;
            connection.sendRequest(string("POST /echo HTTP/1.1\r\nContent-Length: ") + length + "\r\n\r\nhello");
            EXPECT_CALL(invoke, shouldCaptureHeaders("echo")).WillOnce(Return(capture_headers));
            EXPECT_CALL(invoke, isPostCall("echo")).WillOnce(Return(true));
            EXPECT_CALL(invoke, invokePost("echo", "hello")).WillOnce(Return(Maybe<string>(string("ok"))));
            RestConn(connection.server(), &mainloop, &invoke).parseConn();
            EXPECT_THAT(connection.response(), HasSubstr("200 OK"));
        }
    }
}

TEST_F(RestConnInputTest, peer_eof_closes_without_invoking_a_handler)
{
    sockets.sendRequest("GET /");
    ASSERT_EQ(shutdown(sockets.client(), SHUT_WR), 0);
    expectClosed();
    RestConn(sockets.server(), &mainloop, &invoke).parseConn();
}

} // namespace
