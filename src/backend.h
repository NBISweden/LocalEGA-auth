#ifndef __LEGA_BACKEND_H_INCLUDED__
#define __LEGA_BACKEND_H_INCLUDED__

#include <stdbool.h>
#include <pwd.h>
#include <sqlite3.h>

#include "config.h"

bool backend_add_user(const char* username,
		      const char* uid,
		      const char* pwdh,
		      const char* pubkey,
		      const char* gecos,
		      const char* shell);

/* bool backend_user_found(const char* username); */

int backend_getpwnam_r(const char* username, struct passwd *result, char *buffer, size_t buflen);
int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen);

bool backend_username_found(const char* username);
bool backend_uid_found(uid_t uid);

int backend_get_password_hash(const char* username, char** data);
int backend_get_pubkey(const char* username, char** data);

bool backend_opened(void);
void backend_open(void);
void backend_close(void);

#endif /* !__LEGA_BACKEND_H_INCLUDED__ */
