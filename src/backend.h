#ifndef __LEGA_BACKEND_H_INCLUDED__
#define __LEGA_BACKEND_H_INCLUDED__

#include <stdbool.h>
#include <pwd.h>

bool backend_add_user(const char* username, const char* pwdh, const char* pubkey);

bool backend_user_found(const char* username);
int backend_convert(const char* username, struct passwd *result, char *buffer, size_t buflen);

int backend_get_item(const char* username, const char* item, char** content);
int backend_set_item(const char* username, const char* item, const char* content);

#endif /* !__LEGA_BACKEND_H_INCLUDED__ */
