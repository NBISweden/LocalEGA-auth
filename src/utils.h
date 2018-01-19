#ifndef __LEGA_UTILS_H_INCLUDED__
#define __LEGA_UTILS_H_INCLUDED__

#include <syslog.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>

#define _XOPEN_SOURCE 700 /* for stpcpy */
#include <string.h>
#include <stdio.h>

#define DBGLOG(x...) if(options->debug) {						    \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_DEBUG, ##x);                   \
                          closelog();                               \
                      }
#define SYSLOG(x...)  ({                                            \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      })
#define AUTHLOG(x...) ({                                            \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_AUTH, ##x);                    \
                          closelog();                               \
                      })

#define D(...)

#define DECLARE_CLEANUP(name) static inline void free_ ## name (void* p){ free(*(char**)p);} \
  struct __useless_struct_to_allow_trailing_semicolon__


#ifdef DEBUG
#undef D
#define D(fmt, ...) fprintf(stderr, "EGA %-10s | %4d | %22s | "fmt"\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
/* #undef DECLARE_CLEANUP */
/* #define DECLARE_CLEANUP(name)             \ */
/*   static inline void free_ ## name (void* p) \ */
/*   {                                       \ */
/*     fprintf(stderr, "EGA %-10s | %4d | %22s | ========== Freeing "#name" %p -> %p\n", __FILE__, __LINE__, __FUNCTION__, p, *(char**)p); \ */
/*     free(*(char**)p);                     \ */
/*   }                                       \ */
/*   struct __useless_struct_to_allow_trailing_semicolon__ */
#endif /* !DEBUG */

static inline void close_file(FILE** f){ if(*f){ /* D("========== Closing file"); */ fclose(*f); }; }
#define _cleanup_file_ __attribute__((cleanup(close_file)))
#define _cleanup_str_(name) __attribute__((cleanup(free_##name)))


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

static inline int
copy2buffer(const char* data, char** dest, char **bufptr, size_t *buflen)
{
  size_t slen = strlen(data) + 1;

  if(*buflen < slen) {
    D("buffer too small [currently: %zd bytes left] to copy \"%s\" [%zd bytes]", *buflen, data, slen);
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
