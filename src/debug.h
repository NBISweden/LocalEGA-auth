#ifndef __LEGA_DEBUG_H_INCLUDED__
#define __LEGA_DEBUG_H_INCLUDED__

#include <syslog.h>

#define DBGLOG(x...)  if(options->debug) {                          \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_DEBUG, ##x);                   \
                          closelog();                               \
                      }
#define SYSLOG(x...)  do {                                          \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      } while(0);
#define AUTHLOG(x...) do {                                          \
                          openlog("EGA_auth", LOG_PID, LOG_USER);   \
                          syslog(LOG_AUTH, ##x);                    \
                          closelog();                               \
                      } while(0);

#define D(...)


#ifdef DEBUG
#include <stdio.h>
#undef D
#define D(fmt, ...) fprintf(stderr, "EGA %-10s | %4d | %22s | "fmt"\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif /* !DEBUG */

#endif /* !__LEGA_DEBUG_H_INCLUDED__ */
