#ifndef OSLOGIN_UTILS_H_
#define OSLOGIN_UTILS_H_

#include <string>
#include <vector>

namespace oslogin_utils {

const std::string kMetadataServerUrl = "http://127.0.0.1:8080/";

// Simplified structures and functions for local API

struct Group {
    std::string name;
    gid_t gid;
    std::vector<std::string> members;
    bool sudo;
};

class BufferManager {
public:
    BufferManager(char* buffer, size_t buflen) : buffer_(buffer), buflen_(buflen), used_(0) {}
    char* Allocate(size_t size) {
        if (used_ + size > buflen_) return nullptr;
        char* ptr = buffer_ + used_;
        used_ += size;
        return ptr;
    }
private:
    char* buffer_;
    size_t buflen_;
    size_t used_;
};

// Simplified HTTP GET using curl or similar
bool HttpGet(const std::string& url, std::string* response, long* http_code);

// Parse JSON to passwd (simplified)
bool ParseJsonToPasswd(const std::string& json, struct passwd* result, BufferManager* buffer_manager, int* errnop);

// URL encode
std::string UrlEncode(const std::string& str);

// Group functions (simplified)
bool GetGroupByName(const std::string& name, struct group* grp, BufferManager* buffer_manager, int* errnop);
bool GetGroupByGID(gid_t gid, struct group* grp, BufferManager* buffer_manager, int* errnop);
bool GetGroupsForUser(const std::string& username, std::vector<std::string>* groups, int* errnop);
bool GetUsersForGroup(const std::string& groupname, std::vector<std::string>* users, int* errnop);
bool AddUsersToGroup(const std::vector<std::string>& users, struct group* grp, BufferManager* buffer_manager, int* errnop);

}  // namespace oslogin_utils

#endif  // OSLOGIN_UTILS_H_