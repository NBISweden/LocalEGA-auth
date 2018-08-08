#ifndef __LEGA_JSON_H_INCLUDED__
#define __LEGA_JSON_H_INCLUDED__

#include "jsmn/jsmn.h"

int parse_json(const char* json, int jsonlen,
	       char** username, char** pwd, char** pbk, char** gecos, int* uid);

#endif /* !__LEGA_JSON_H_INCLUDED__ */
