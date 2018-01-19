#ifndef __LEGA_BACKEND_H_INCLUDED__
#define __LEGA_BACKEND_H_INCLUDED__

#include <stdbool.h>
#include <nss.h>
#include <pwd.h>
#include <errno.h>

bool backend_open(int stayopen);

void backend_close(void);

int backend_add_user(const char* username, const char* pwdh, const char* pubkey,
		      char **buffer, size_t *buflen);

int backend_account_valid(const char* username);
int backend_refresh_user(const char* username);

enum nss_status backend_convert(const char* username, struct passwd *result,
				char **buffer, size_t *buflen, int *errnop);

int backend_get_item(const char* username, const char* item,
		     char** content, char** bufptr, size_t* buflen);

#endif /* !__LEGA_BACKEND_H_INCLUDED__ */
