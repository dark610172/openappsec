#ifndef RATE_LIMIT_IP_H
#define RATE_LIMIT_IP_H

#include <arpa/inet.h>
#include <string>

#include "connkey.h"

inline std::string
ipAddrToStr(const IPAddr &ip_address)
{
    char buffer[INET6_ADDRSTRLEN];
    const char *formatted = nullptr;
    switch (ip_address.getType()) {
        case IPType::V4:
            formatted = inet_ntop(AF_INET, &ip_address.getIPv4(), buffer, sizeof(buffer));
            break;
        case IPType::V6:
            formatted = inet_ntop(AF_INET6, &ip_address.getIPv6(), buffer, sizeof(buffer));
            break;
        default:
            return "";
    }
    return formatted == nullptr ? "" : std::string(formatted);
}

#endif // RATE_LIMIT_IP_H
