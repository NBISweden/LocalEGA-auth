#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <curl/curl.h>
#include <jq.h>

#include "debug.h"
#include "config.h"
#include "backend.h"

#define URL_SIZE 1024

struct curl_res_s {
  char *body;
  size_t size;
};

/* callback for curl fetch */
size_t
curl_callback (void* contents, size_t size, size_t nmemb, void* userdata) {
  const size_t realsize = size * nmemb;                      /* calculate buffer size */
  struct curl_res_s *cres = (struct curl_res_s*) userdata;   /* cast pointer to fetch struct */

  /* expand buffer */
  D("cres->body: %s", cres->body);
  D("cres->size: %zd", cres->size);
  D("change to %zd", cres->size + realsize + 1);
  cres->body = (char *) realloc(cres->body, cres->size + realsize + 1);

  /* check buffer */
  if (cres->body == NULL) { D("ERROR: Failed to expand buffer in curl_callback"); return -1; }

  /* copy contents to buffer */
  memcpy(&(cres->body[cres->size]), contents, realsize);
  cres->size += realsize;
  cres->body[cres->size] = '\0';

  return realsize;
}

static const char*
get_from_json(jq_state *jq, const char* query, jv json){
  
  const char* res = NULL;

  D("Processing query: %s", query);

  if (!jq_compile(jq, query)){ D("Invalid query"); return NULL; }

  jq_start(jq, json, 0); // no flags
  jv result = jq_next(jq);
  if(jv_is_valid(result)){

    if (jv_get_kind(result) == JV_KIND_STRING) {
      res = jv_string_value(result);
      D("Valid result: %s", res);
      jv_free(result);
    } else {
      D("Valid result but not a string");
      //jv_dump(result, 0);
      jv_free(result);
    }
  }
  return res;
}

int
fetch_from_cega(const char *username, char **buffer, size_t *buflen)
{
  CURL *curl;
  CURLcode res;
  int rc = 1;
  char* endpoint = NULL;
  char* endpoint_creds = NULL;
  struct curl_res_s *cres = NULL;
  jv parsed_response;
  jq_state* jq = NULL;
  const char *pwd = NULL;
  const char *pbk = NULL;

  D("Contacting cega for user: %s", username);

  if(!options->cega_user || !options->cega_password){
    D("Empty CEGA credentials");
    return 1; /* early quit */
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if(!curl) { D("libcurl init failed"); goto BAILOUT; }

  /* Formatting the endpoint */
  size_t clen = strlen(options->cega_endpoint) - 2; // %s
  size_t ulen = strlen(username);

  if(*buflen < clen+ulen+1) { D("Buffer too small"); rc = -1; goto BAILOUT; }

  endpoint = *buffer;
  if( sprintf(endpoint, options->cega_endpoint, username) < 1 ){
    D("Endpoint URL looks weird for user %s: %s", username, options->cega_endpoint);
    goto BAILOUT;
  }
  *buffer += strlen(endpoint) + 1;
  *buflen -= strlen(endpoint) + 1;
  D("CEGA endpoint: %s", endpoint);

  /* Formatting the endpoint_creds */
  size_t culen = strlen(options->cega_user);
  size_t cplen = strlen(options->cega_password);

  if(*buflen < culen+cplen+1) { D("Buffer too small"); rc = -1; goto BAILOUT; }

  endpoint_creds = *buffer;
  strncpy(*buffer, options->cega_user, culen);
  (*buffer)[culen] = ':';
  *buffer += culen + 1;
  strncpy(*buffer, options->cega_password, cplen);
  (*buffer)[cplen] = '\0';
  *buffer += cplen + 1;
  *buflen -= culen + cplen + 1;
  D("CEGA credentials: %s", endpoint_creds);

  /* Preparing CURL */
  D("Preparing CURL");
  cres = (struct curl_res_s*)malloc(sizeof(struct curl_res_s));
  cres->body = NULL;
  cres->size = 0;

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS    , 1L               ); /* shut off the progress meter */
  curl_easy_setopt(curl, CURLOPT_URL           , endpoint         );
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curl_callback    );
  curl_easy_setopt(curl, CURLOPT_WRITEDATA     , (void*)cres      );
  curl_easy_setopt(curl, CURLOPT_FAILONERROR   , 1L               ); /* when not 200 */
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH      , CURLAUTH_BASIC);
  curl_easy_setopt(curl, CURLOPT_USERPWD       , endpoint_creds);
  /* curl_easy_setopt(curl, CURLOPT_SSLCERT      , options->ssl_cert); */
  /* curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE  , "PEM"            ); */

#ifdef DEBUG
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  D("CEGA Request done");
  if(res != CURLE_OK){
    D("curl_easy_perform() failed: %s", curl_easy_strerror(res));
    goto BAILOUT;
  }

  D("Parsing the JSON response");
  parsed_response = jv_parse(cres->body);

  if (!jv_is_valid(parsed_response)) {
    D("Invalid response");
    goto BAILOUT;
  }

  /* Preparing the queries */
  jq = jq_init();
  if (jq == NULL) { D("jq error with malloc"); goto BAILOUT; }

  pwd = get_from_json(jq, options->cega_resp_passwd, jv_copy(parsed_response));
  pbk = get_from_json(jq, options->cega_resp_pubkey, jv_copy(parsed_response));

  jv_free(parsed_response);

  /* Adding to the database */
  rc = backend_add_user(username, pwd, pbk, buffer, buflen);

BAILOUT:
  D("User %s%s found", username, (rc)?" not":"");
  if(rc) D("Error: %d", rc);
  jq_teardown(&jq);
  if(cres) free(cres);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return rc;
}
