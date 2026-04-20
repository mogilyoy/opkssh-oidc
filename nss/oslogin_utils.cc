#include "include/oslogin_utils.h"
#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <regex>

namespace oslogin_utils {

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    s->append((char*)contents, newLength);
    return newLength;
}

bool HttpGet(const std::string& url, std::string* response, long* http_code) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    curl_easy_cleanup(curl);

    return res == CURLE_OK;
}

std::string UrlEncode(const std::string& str) {
    CURL* curl = curl_easy_init();
    if (!curl) return str;
    char* encoded = curl_easy_escape(curl, str.c_str(), str.length());
    std::string result = encoded;
    curl_free(encoded);
    curl_easy_cleanup(curl);
    return result;
}

bool ParseJsonToPasswd(const std::string& json, struct passwd* result, BufferManager* buffer_manager, int* errnop) {
    // Simple JSON parsing for {"Username":"alice","Email":"alice@example.com","FullName":"Alice Example","HomeDirectory":"/home/alice","UID":1001,"GID":1001,"Groups":["cluster-1:admin","cluster-1:dev"],"SSHKeys":["ssh-ed25519 ..."]}
    std::regex username_regex("\"Username\"\\s*:\\s*\"([^\"]+)\"");
    std::regex uid_regex("\"UID\"\\s*:\\s*(\\d+)");
    std::regex gid_regex("\"GID\"\\s*:\\s*(\\d+)");
    std::regex home_regex("\"HomeDirectory\"\\s*:\\s*\"([^\"]+)\"");
    std::regex fullname_regex("\"FullName\"\\s*:\\s*\"([^\"]+)\"");

    std::smatch match;
    std::string username, home, gecos;
    uid_t uid = 0;
    gid_t gid = 0;

    if (std::regex_search(json, match, username_regex)) {
        username = match[1];
    } else {
        *errnop = EINVAL;
        return false;
    }

    if (std::regex_search(json, match, uid_regex)) {
        uid = std::stoi(match[1]);
    } else {
        *errnop = EINVAL;
        return false;
    }

    if (std::regex_search(json, match, gid_regex)) {
        gid = std::stoi(match[1]);
    } else {
        *errnop = EINVAL;
        return false;
    }

    if (std::regex_search(json, match, home_regex)) {
        home = match[1];
    } else {
        home = "/home/" + username;
    }

    if (std::regex_search(json, match, fullname_regex)) {
        gecos = match[1];
    } else {
        gecos = username;
    }

    std::string shell = "/bin/bash";

    char* username_buf = buffer_manager->Allocate(username.size() + 1);
    if (!username_buf) { *errnop = ERANGE; return false; }
    strcpy(username_buf, username.c_str());

    char* home_buf = buffer_manager->Allocate(home.size() + 1);
    if (!home_buf) { *errnop = ERANGE; return false; }
    strcpy(home_buf, home.c_str());

    char* shell_buf = buffer_manager->Allocate(shell.size() + 1);
    if (!shell_buf) { *errnop = ERANGE; return false; }
    strcpy(shell_buf, shell.c_str());

    char* gecos_buf = buffer_manager->Allocate(gecos.size() + 1);
    if (!gecos_buf) { *errnop = ERANGE; return false; }
    strcpy(gecos_buf, gecos.c_str());

    result->pw_name = username_buf;
    result->pw_uid = uid;
    result->pw_gid = gid;
    result->pw_dir = home_buf;
    result->pw_shell = shell_buf;
    result->pw_gecos = gecos_buf;
    result->pw_passwd = (char*)"*";

    return true;
}

// Simplified group functions - for now, return empty or default
bool GetGroupByName(const std::string& name, struct group* grp, BufferManager* buffer_manager, int* errnop) {
    // Query /groups?name=<name>
    std::stringstream url;
    url << kMetadataServerUrl << "groups?name=" << UrlEncode(name);
    std::string response;
    long http_code;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200) {
        *errnop = ENOENT;
        return false;
    }

    // Simple parse {"Name":"cluster-1:admin","GID":2001,"Members":["alice"],"Sudo":true}
    std::regex name_regex("\"Name\"\\s*:\\s*\"([^\"]+)\"");
    std::regex gid_regex("\"GID\"\\s*:\\s*(\\d+)");

    std::smatch match;
    std::string groupname;
    gid_t gid = 0;

    if (std::regex_search(response, match, name_regex)) {
        groupname = match[1];
    } else {
        *errnop = EINVAL;
        return false;
    }

    if (std::regex_search(response, match, gid_regex)) {
        gid = std::stoi(match[1]);
    } else {
        *errnop = EINVAL;
        return false;
    }

    char* name_buf = buffer_manager->Allocate(groupname.size() + 1);
    if (!name_buf) { *errnop = ERANGE; return false; }
    strcpy(name_buf, groupname.c_str());

    grp->gr_name = name_buf;
    grp->gr_gid = gid;
    grp->gr_passwd = (char*)"*";
    grp->gr_mem = nullptr;  // Will be set by caller

    return true;
}

bool GetGroupByGID(gid_t gid, struct group* grp, BufferManager* buffer_manager, int* errnop) {
    // Similar
    std::stringstream url;
    url << kMetadataServerUrl << "groups?gid=" << gid;
    std::string response;
    long http_code;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200) {
        *errnop = ENOENT;
        return false;
    }

    std::regex name_regex("\"Name\"\\s*:\\s*\"([^\"]+)\"");
    std::regex ggid_regex("\"GID\"\\s*:\\s*(\\d+)");

    std::smatch match;
    std::string groupname;
    gid_t ggid = 0;

    if (std::regex_search(response, match, name_regex)) {
        groupname = match[1];
    } else {
        *errnop = EINVAL;
        return false;
    }

    if (std::regex_search(response, match, ggid_regex)) {
        ggid = std::stoi(match[1]);
    } else {
        *errnop = EINVAL;
        return false;
    }

    char* name_buf = buffer_manager->Allocate(groupname.size() + 1);
    if (!name_buf) { *errnop = ERANGE; return false; }
    strcpy(name_buf, groupname.c_str());

    grp->gr_name = name_buf;
    grp->gr_gid = ggid;
    grp->gr_passwd = (char*)"*";
    grp->gr_mem = nullptr;

    return true;
}

bool GetGroupsForUser(const std::string& username, std::vector<std::string>* groups, int* errnop) {
    // Query /users?username=<username> and parse Groups array
    std::stringstream url;
    url << kMetadataServerUrl << "users?username=" << UrlEncode(username);
    std::string response;
    long http_code;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200) {
        *errnop = ENOENT;
        return false;
    }

    // Parse "Groups":["cluster-1:admin","cluster-1:dev"]
    std::regex groups_regex("\"Groups\"\\s*:\\s*\\[([^\\]]+)\\]");
    std::smatch match;
    if (std::regex_search(response, match, groups_regex)) {
        std::string groups_str = match[1];
        std::regex group_regex("\"([^\"]+)\"");
        std::sregex_iterator iter(groups_str.begin(), groups_str.end(), group_regex);
        std::sregex_iterator end;
        for (; iter != end; ++iter) {
            groups->push_back((*iter)[1]);
        }
    }

    return true;
}

bool GetUsersForGroup(const std::string& groupname, std::vector<std::string>* users, int* errnop) {
    // Query /groups?name=<groupname> and parse Members array
    std::stringstream url;
    url << kMetadataServerUrl << "groups?name=" << UrlEncode(groupname);
    std::string response;
    long http_code;
    if (!HttpGet(url.str(), &response, &http_code) || http_code != 200) {
        *errnop = ENOENT;
        return false;
    }

    // Parse "Members":["alice"]
    std::regex members_regex("\"Members\"\\s*:\\s*\\[([^\\]]+)\\]");
    std::smatch match;
    if (std::regex_search(response, match, members_regex)) {
        std::string members_str = match[1];
        std::regex member_regex("\"([^\"]+)\"");
        std::sregex_iterator iter(members_str.begin(), members_str.end(), member_regex);
        std::sregex_iterator end;
        for (; iter != end; ++iter) {
            users->push_back((*iter)[1]);
        }
    }

    return true;
}

bool AddUsersToGroup(const std::vector<std::string>& users, struct group* grp, BufferManager* buffer_manager, int* errnop) {
    if (users.empty()) {
        grp->gr_mem = nullptr;
        return true;
    }

    char** mem = (char**)buffer_manager->Allocate((users.size() + 1) * sizeof(char*));
    if (!mem) { *errnop = ERANGE; return false; }

    for (size_t i = 0; i < users.size(); ++i) {
        char* user_buf = buffer_manager->Allocate(users[i].size() + 1);
        if (!user_buf) { *errnop = ERANGE; return false; }
        strcpy(user_buf, users[i].c_str());
        mem[i] = user_buf;
    }
    mem[users.size()] = nullptr;
    grp->gr_mem = mem;
    return true;
}

}  // namespace oslogin_utils