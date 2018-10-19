#ifndef __LEGA_CENTRAL_H_INCLUDED__
#define __LEGA_CENTRAL_H_INCLUDED__

#include <sys/types.h>

int cega_resolve(const char *endpoint,
		 int (*cb)(char* username, uid_t uid, char* password_hash, char* pubkey, char* gecos));

#endif /* !__LEGA_CENTRAL_H_INCLUDED__ */
