// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

#ifndef ATTACHMENT_CONFIG_PUBLISHER_H
#define ATTACHMENT_CONFIG_PUBLISHER_H

#include <fstream>
#include <string>

inline bool
writeAttachmentSettings(const std::string &path, const std::string &content)
{
    std::ofstream stream(path, std::ofstream::out);
    if (!stream.is_open()) return false;
    stream << content;
    stream.close();
    return !stream.fail();
}

// Keep the publication gate independent of the attachment's IPC and configuration services.
class AttachmentConfigPublisher
{
public:
    template <typename Config, typename Writer, typename Notify>
    bool
    publish(
        const Config &candidate,
        Config &committed,
        unsigned int &ipc_elements,
        const Writer &write,
        const Notify &notify
    )
    {
        if (!published || !(committed == candidate)) {
            // The writer may remove/truncate the previous file even when it fails.
            published = false;
            if (!write()) return false;
            committed = candidate;
            ipc_elements = candidate.getNumOfNginxElements();
            published = true;
        }
        notify();
        return true;
    }

private:
    bool published = false;
};

#endif // ATTACHMENT_CONFIG_PUBLISHER_H
