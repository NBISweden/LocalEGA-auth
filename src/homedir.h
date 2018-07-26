#ifndef __LEGA_HOMEDIR_H_INCLUDED__
#define __LEGA_HOMEDIR_H_INCLUDED__

#include <stdbool.h>
#include <pwd.h>

bool create_ega_dir(const struct passwd *result, const long int attrs);
void remove_ega_dir(const char*, const char*);

#endif /* !__LEGA_HOMEDIR_H_INCLUDED__ */
