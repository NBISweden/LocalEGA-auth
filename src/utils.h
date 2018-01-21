#ifndef __LEGA_UTILS_H_INCLUDED__
#define __LEGA_UTILS_H_INCLUDED__

#include <syslog.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>

#define _XOPEN_SOURCE 700 /* for stpcpy */
#include <string.h>
#include <stdio.h>

#define D1(...)
#define D2(...)
#define D3(...)

#ifdef DEBUG
#include <unistd.h>

#if DEBUG > 0
#undef D1
#define D1(fmt, ...) fprintf(stderr, "[%5d] %-10s(%3d)%22s | "fmt"\n", getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#endif

#if DEBUG > 1
#undef D2
#define D2(fmt, ...) fprintf(stderr, "[%5d] %-10s(%3d)%22s | \t"fmt"\n", getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#endif

#if DEBUG > 2
#undef D3
#define D3(fmt, ...) fprintf(stderr, "[%5d] %-10s(%3d)%22s | \t\t"fmt"\n", getpid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#endif

#endif /* !DEBUG */

/*
 * Using compiler __attribute__ to cleanup on return of scope
 *
 * See: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html
 * And  http://echorand.me/site/notes/articles/c_cleanup/cleanup_attribute_c.html
 */
static inline void close_file(FILE** f){ if(*f){ D3("Closing file"); fclose(*f); }; }
#define _cleanup_file_ __attribute__((cleanup(close_file)))

static inline void free_str(char** p){ D3("Freeing %p", *p); free(*p); }
#define _cleanup_str_ __attribute__((cleanup(free_str)))

/*
 * Concatenate string and allocate them on the stack.
 * That way, no need to free them from the heap
 */
#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

#define strjoina(a, ...)                                                                                   \
        ({                                                                                                 \
                const char* _arr_[] = { a, __VA_ARGS__ };                                                  \
                char *_d_, *_p_; size_t _len_ = 0; unsigned _i_;                                           \
                for (_i_ = 0; _i_ < ELEMENTSOF(_arr_) && _arr_[_i_]; _i_++) _len_ += strlen(_arr_[_i_]);   \
                _p_ = _d_ = alloca(_len_ + 1);                                                             \
                for (_i_ = 0; _i_ < ELEMENTSOF(_arr_) && _arr_[_i_]; _i_++) _p_ = stpcpy(_p_, _arr_[_i_]); \
                *_p_ = 0;                                                                                  \
                _d_;                                                                                       \
        })

/*
 * Moves a string value to a buffer (including a \0 at the end).
 * Adjusts the pointer to pointer right after the \0.
 *
 * Returns -size in case the buffer is <size> too small.
 * Otherwise, returns the <size> of the string.
 */
static inline int
copy2buffer(const char* data, char** dest, char **bufptr, size_t *buflen)
{
  size_t slen = strlen(data) + 1;

  if(*buflen < slen) {
    D3("buffer too small [currently: %zd bytes left] to copy \"%s\" [%zd bytes]", *buflen, data, slen);
    return -slen;
  }

  strncpy(*bufptr, data, slen-1);
  (*bufptr)[slen-1] = '\0';
  
  if(dest) *dest = *bufptr; /* record location */
  *bufptr += slen;
  *buflen -= slen;
  
  return slen;
}


#endif /* !__LEGA_UTILS_H_INCLUDED__ */
