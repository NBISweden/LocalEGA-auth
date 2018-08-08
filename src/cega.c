#include <curl/curl.h>
#include <sys/types.h>

#include "utils.h"
#include "backend.h"
#include "json.h"
#include "cega.h"

struct curl_res_s {
  char *body;
  size_t size;
};


/* callback for curl fetch */
size_t
curl_callback (void* contents, size_t size, size_t nmemb, void* userdata) {
  const size_t realsize = size * nmemb;                      /* calculate buffer size */
  struct curl_res_s *r = (struct curl_res_s*) userdata;   /* cast pointer to fetch struct */

  /* expand buffer */
  r->body = (char *) realloc(r->body, r->size + realsize + 1);

  /* check buffer */
  if (r->body == NULL) { D2("ERROR: Failed to expand buffer for cURL"); return -1; }

  /* copy contents to buffer */
  memcpy(&(r->body[r->size]), contents, realsize);
  r->size += realsize;
  r->body[r->size] = '\0';

  return realsize;
}

int
cega_resolve(const char *endpoint,
	     int (*cb)(char*, uid_t, char*, char*, char*))
{
  int rc = 1; /* error */
  struct curl_res_s* cres = NULL;
  CURL* curl = NULL;
  char *username = NULL;
  char *pwd = NULL;
  char *pbk = NULL;
  char *gecos = NULL;
  int uid = -1;

  D1("Contacting %s", endpoint);

  /* Preparing cURL */
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if(!curl) { D2("libcurl init failed"); goto BAILOUT; }

  /* Preparing result */
  cres = (struct curl_res_s*)malloc(sizeof(struct curl_res_s));
  if(!cres){ D1("memory allocation failure for the cURL result"); goto BAILOUT; }
  cres->body = NULL;
  cres->size = 0;

  /* Preparing the request */
  curl_easy_setopt(curl, CURLOPT_URL           , endpoint         );
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curl_callback    );
  curl_easy_setopt(curl, CURLOPT_WRITEDATA     , (void*)cres      );
  curl_easy_setopt(curl, CURLOPT_FAILONERROR   , 1L               ); /* when not 200 */
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH      , CURLAUTH_BASIC);
  curl_easy_setopt(curl, CURLOPT_USERPWD       , options->cega_creds);
  /* curl_easy_setopt(curl, CURLOPT_NOPROGRESS    , 0L               ); */ /* enable progress meter */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERT      , options->ssl_cert); */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE  , "PEM"            ); */

#ifdef DEBUG
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  /* Perform the request */
  CURLcode res = curl_easy_perform(curl);
  if(res != CURLE_OK){ D2("curl_easy_perform() failed: %s", curl_easy_strerror(res)); goto BAILOUT; }

  /* Successful cURL */
  D1("JSON string [size %zu]: %s", cres->size, cres->body);
  
  D2("Parsing the JSON response");
  rc = parse_json(cres->body, cres->size, 
		  &username, &pwd, &pbk, &gecos, &uid);

  if(rc) { D1("We found %d errors", rc); goto BAILOUT; }

  /* Checking the data */
  if( !username ) rc++;
  if( !pwd && !pbk ) rc++;
  if( uid <= 0 ) rc++;
  /* if( !gecos ) rc++; */
  if( !gecos ) gecos = strdup("LocalEGA User");

  if(rc) { D1("We found %d errors", rc); goto BAILOUT; }

  /* Callback: What to do with the data */
  rc = cb(username, (uid_t)(uid + options->uid_shift), pwd, pbk, gecos);

BAILOUT:
  if(cres->body)free(cres->body);
  if(cres)free(cres);
  if(username){ D1("Freeing username at %p", username); free(username); }
  if(pwd){ D1("Freeing pwd at %p", pwd); free(pwd); }
  if(pbk){ D1("Freeing pbk at %p", pbk); free(pbk); }
  if(gecos){ D1("Freeing gecos at %p", gecos ); free(gecos); }
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return rc;
}
