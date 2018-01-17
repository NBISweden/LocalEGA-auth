#ifndef __LEGA_CENTRAL_H_INCLUDED__
#define __LEGA_CENTRAL_H_INCLUDED__

#include <stdbool.h>

int fetch_from_cega(const char *username, char **buffer, size_t *buflen, int *errnop);

#endif /* !__LEGA_CENTRAL_H_INCLUDED__ */
