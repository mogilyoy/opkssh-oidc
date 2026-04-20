// Copyright 2017 Google Inc. All Rights Reserved.
//
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

#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "include/compat.h"
#include "include/oslogin_utils.h"

#define MAXBUFSIZE 32768
#define PASSWD_PATH "/etc/passwd"

using std::string;

using oslogin_utils::AddUsersToGroup;
using oslogin_utils::BufferManager;
using oslogin_utils::GetGroupByName;
using oslogin_utils::GetGroupByGID;
using oslogin_utils::GetGroupsForUser;
using oslogin_utils::GetUsersForGroup;
using oslogin_utils::HttpGet;
using oslogin_utils::kMetadataServerUrl;
using oslogin_utils::ParseJsonToPasswd;
using oslogin_utils::UrlEncode;

// Helper: allocate and copy a string into the NSS buffer.
static bool BufferAppendString(BufferManager& bm, const char* src, char** dest, int* errnop) {
  size_t len = strlen(src) + 1;
  char* buf = bm.Allocate(len);
  if (!buf) {
    *errnop = ERANGE;
    return false;
  }
  memcpy(buf, src, len);
  *dest = buf;
  return true;
}

extern "C" {

// Get a passwd entry by id.
enum nss_status
_nss_oslogin_getpwuid_r(uid_t uid, struct passwd *result,
                        char *buffer, size_t buflen, int *errnop) {
  BufferManager buffer_manager(buffer, buflen);
  std::stringstream url;
  url << kMetadataServerUrl << "users?uid=" << uid;

  string response;
  long http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) ||
      http_code != 200 || response.empty()) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }

  if (!ParseJsonToPasswd(response, result, &buffer_manager, errnop)) {
    if (*errnop == EINVAL) {
      openlog("nss_oslogin", LOG_PID, LOG_USER);
      syslog(LOG_ERR, "Received malformed response from server: %s",
             response.c_str());
      closelog();
    }
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Get a passwd entry by name.
enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result,
                        char *buffer, size_t buflen, int *errnop) {
  BufferManager buffer_manager(buffer, buflen);
  std::stringstream url;
  url << kMetadataServerUrl << "users?username=" << UrlEncode(name);

  string response;
  long http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) ||
      http_code != 200 || response.empty()) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }

  if (!ParseJsonToPasswd(response, result, &buffer_manager, errnop)) {
    if (*errnop == EINVAL) {
      openlog("nss_oslogin", LOG_PID, LOG_USER);
      syslog(LOG_ERR, "Received malformed response from server: %s",
             response.c_str());
      closelog();
    }
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Look for OS Login user with uid matching the requested gid, and craft a
// self-group for it.
enum nss_status
getselfgrgid(gid_t gid, struct group *grp, char *buf,
             size_t buflen, int *errnop) {
  BufferManager buffer_manager(buf, buflen);

  // Look for a matching user in cache.
  FILE *p_file = fopen(OSLOGIN_PASSWD_CACHE_PATH, "re");
  if (p_file != NULL) {
    struct passwd user;
    struct passwd *userp = NULL;
    char userbuf[MAXBUFSIZE];

    while (fgetpwent_r(p_file, &user, userbuf, MAXBUFSIZE, &userp) == 0) {
      if (user.pw_uid == gid) {
        memset(grp, 0, sizeof(struct group));

        if (!BufferAppendString(buffer_manager, user.pw_name, &grp->gr_name, errnop)) {
          fclose(p_file);
          return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
        }

        // Add user to group.
        std::vector<string> members;
        members.push_back(string(user.pw_name));
        if (!AddUsersToGroup(members, grp, &buffer_manager, errnop)) {
          fclose(p_file);
          return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
        }

        fclose(p_file);
        return NSS_STATUS_SUCCESS;
      }
    }
    fclose(p_file);
  }

  // Look for matching user in backend.
  std::stringstream url;
  url << kMetadataServerUrl << "users?uid=" << gid;

  string response;
  long http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) ||
      http_code != 200 || response.empty()) {
    return NSS_STATUS_NOTFOUND;
  }

  struct passwd result;
  if (!ParseJsonToPasswd(response, &result, &buffer_manager, errnop)) {
    return NSS_STATUS_NOTFOUND;
  }

  if (result.pw_gid != result.pw_uid) {
    return NSS_STATUS_NOTFOUND;
  }
  if (!BufferAppendString(buffer_manager, result.pw_name, &grp->gr_name, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }

  grp->gr_gid = result.pw_uid;

  std::vector<string> members;
  members.push_back(string(result.pw_name));
  if (!AddUsersToGroup(members, grp, &buffer_manager, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Look for OS Login user with name matching the requested name, and craft a
// self-group for it.
enum nss_status
getselfgrnam(const char* name, struct group *grp,
             char *buf, size_t buflen, int *errnop) {
  BufferManager buffer_manager(buf, buflen);

  // Look for a matching user in cache.
  FILE *p_file = fopen(OSLOGIN_PASSWD_CACHE_PATH, "re");
  if (p_file != NULL) {
    struct passwd user;
    struct passwd *userp = NULL;
    char userbuf[MAXBUFSIZE];

    while (fgetpwent_r(p_file, &user, userbuf, MAXBUFSIZE, &userp) == 0) {
      if (strcmp(user.pw_name, name) == 0) {
        memset(grp, 0, sizeof(struct group));

        grp->gr_gid = user.pw_uid;

        std::vector<string> members;
        members.push_back(string(name));
        if (!AddUsersToGroup(members, grp, &buffer_manager, errnop)) {
          fclose(p_file);
          return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
        }

        fclose(p_file);
        return NSS_STATUS_SUCCESS;
      }
    }
    fclose(p_file);
  }

  // Look for matching user in backend.
  std::stringstream url;
  url << kMetadataServerUrl << "users?username=" << UrlEncode(string(name));

  string response;
  long http_code = 0;
  if (!HttpGet(url.str(), &response, &http_code) ||
      http_code != 200 || response.empty()) {
    return NSS_STATUS_NOTFOUND;
  }

  struct passwd result;
  if (!ParseJsonToPasswd(response, &result, &buffer_manager, errnop)) {
    return NSS_STATUS_NOTFOUND;
  }

  if (result.pw_gid != result.pw_uid) {
    return NSS_STATUS_NOTFOUND;
  }
  if (!BufferAppendString(buffer_manager, result.pw_name, &grp->gr_name, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }

  grp->gr_gid = result.pw_uid;

  std::vector<string> members;
  members.push_back(string(result.pw_name));
  if (!AddUsersToGroup(members, grp, &buffer_manager, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Get a group entry by id.
enum nss_status
_nss_oslogin_getgrgid_r(gid_t gid, struct group *grp, char *buf,
                        size_t buflen, int *errnop) {
  memset(grp, 0, sizeof(struct group));
  BufferManager buffer_manager(buf, buflen);
  if (!GetGroupByGID(gid, grp, &buffer_manager, errnop)) {
    if (*errnop == ERANGE) {
      return NSS_STATUS_TRYAGAIN;
    }
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }

  std::vector<string> users;
  if (!GetUsersForGroup(grp->gr_name, &users, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }

  if (!users.empty() && !AddUsersToGroup(users, grp, &buffer_manager, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Get a group entry by name.
enum nss_status
_nss_oslogin_getgrnam_r(const char *name, struct group *grp,
                        char *buf, size_t buflen, int *errnop) {
  memset(grp, 0, sizeof(struct group));
  BufferManager buffer_manager(buf, buflen);
  if (!GetGroupByName(string(name), grp, &buffer_manager, errnop)) {
    if (*errnop == ERANGE) {
      return NSS_STATUS_TRYAGAIN;
    }
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }

  std::vector<string> users;
  if (!GetUsersForGroup(grp->gr_name, &users, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }

  if (!users.empty() && !AddUsersToGroup(users, grp, &buffer_manager, errnop)) {
    return *errnop == ERANGE ? NSS_STATUS_TRYAGAIN : NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}

// Initialize groups for new session.
enum nss_status
_nss_oslogin_initgroups_dyn(const char *user, gid_t /* skipgroup */, long int *start,
                            long int *size, gid_t **groupsp,
                            long int limit, int *errnop) {
  // Check if user exists in local passwd DB — skip if so.
  FILE *p_file = fopen(PASSWD_PATH, "re");
  if (p_file == NULL) {
    return NSS_STATUS_NOTFOUND;
  }

  struct passwd *userp;
  while ((userp = fgetpwent(p_file)) != NULL) {
    if (strcmp(userp->pw_name, user) == 0) {
      fclose(p_file);
      return NSS_STATUS_NOTFOUND;
    }
  }
  fclose(p_file);

  std::vector<string> groupnames;
  if (!GetGroupsForUser(string(user), &groupnames, errnop)) {
      return NSS_STATUS_NOTFOUND;
  }

  // For each group name, resolve GID via the API.
  gid_t *groups = *groupsp;
  for (size_t i = 0; i < groupnames.size(); i++) {
    if (*start == *size) {
      gid_t *newgroups;
      long int newsize = 2 * *size;
      if (limit > 0) {
        if (*size >= limit) {
          *errnop = ERANGE;
          return NSS_STATUS_TRYAGAIN;
        }
        newsize = MIN(limit, newsize);
      }
      newgroups = (gid_t *)realloc(groups, newsize * sizeof(gid_t));
      if (newgroups == NULL) {
        *errnop = EAGAIN;
        return NSS_STATUS_TRYAGAIN;
      }
      *groupsp = groups = newgroups;
      *size = newsize;
    }

    // Resolve group name to GID.
    struct group grp;
    char grpbuf[MAXBUFSIZE];
    BufferManager bm(grpbuf, sizeof(grpbuf));
    int grp_errno = 0;
    if (GetGroupByName(groupnames[i], &grp, &bm, &grp_errno)) {
      groups[(*start)++] = grp.gr_gid;
    }
  }

  return NSS_STATUS_SUCCESS;
}

// Stubs — enumeration is not supported.
nss_status _nss_oslogin_getpwent_r() { return NSS_STATUS_NOTFOUND; }
nss_status _nss_oslogin_endpwent() { return NSS_STATUS_SUCCESS; }
nss_status _nss_oslogin_setpwent() { return NSS_STATUS_SUCCESS; }

nss_status _nss_oslogin_getgrent_r() { return NSS_STATUS_NOTFOUND; }
nss_status _nss_oslogin_endgrent() { return NSS_STATUS_SUCCESS; }
nss_status _nss_oslogin_setgrent() { return NSS_STATUS_SUCCESS; }

}  // extern "C"
