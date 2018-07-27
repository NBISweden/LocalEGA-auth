#ifndef __LEGA_BACKEND_H_INCLUDED__
#define __LEGA_BACKEND_H_INCLUDED__

#include <stdbool.h>
#include <pwd.h>
#include <sqlite3.h>

#if SQLITE_VERSION_NUMBER < 3024000
  #error Only SQLite 3.24+ supported
#endif

#include "config.h"

int backend_add_user(const char* username,
		     uid_t uid,
		     const char* pwdh,
		     const char* pubkey,
		     const char* gecos);

int backend_getpwnam_r(const char* username, struct passwd *result, char *buffer, size_t buflen);
int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen);

int backend_get_password_hash(const char* username, char** data);
bool backend_print_pubkey(const char* username);

bool backend_opened(void);
void backend_open(void);
void backend_close(void);

#endif /* !__LEGA_BACKEND_H_INCLUDED__ */
