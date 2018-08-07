#include <curl/curl.h>
#include <jq.h>
#include <pwd.h>

#include "utils.h"
#include "backend.h"
#include "cega.h"

/* Will be appended to options->cega_json_prefix */
#define CEGA_JSON_USER  ".username"
#define CEGA_JSON_UID   ".uid"
#define CEGA_JSON_PWD   ".password_hash"
#define CEGA_JSON_PBK   ".pubkey"
#define CEGA_JSON_GECOS ".gecos"

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
  cres->body = (char *) realloc(cres->body, cres->size + realsize + 1);

  /* check buffer */
  if (cres->body == NULL) { D2("ERROR: Failed to expand buffer in curl_callback"); return -1; }

  /* copy contents to buffer */
  memcpy(&(cres->body[cres->size]), contents, realsize);
  cres->size += realsize;
  cres->body[cres->size] = '\0';

  return realsize;
}

static int
json2str(jq_state *jq, const char* query_end, jv json, char** res){

  char* query = strjoina(options->cega_json_prefix, query_end);
  D3("Processing query: %s", query);

  if (!jq_compile(jq, query)){ D3("Invalid query"); return 1; }

  jq_start(jq, json, 0); // no flags
  jv result = jq_next(jq);
  if(jv_is_valid(result)){ // no consume

    if(jv_get_kind(result) == JV_KIND_STRING) { // no consume
      D3("Processing a string");
      *res = (char*)jv_string_value(result); // consumed
      D3("Valid result: %s", *res);
    } else {
      D3("Valid result but not a string");
      //jv_dump(result, 0);
      jv_free(result);
    }
  }
  return 0;
}

static int
json2int(jq_state *jq, const char* query_end, jv json, int* res){

  char* query = strjoina(options->cega_json_prefix, query_end);
  D3("Processing query: %s", query);

  if (!jq_compile(jq, query)){ D3("Invalid query"); return 1; }

  jq_start(jq, json, 0); // no flags
  jv result = jq_next(jq);
  if(jv_is_valid(result)){ // no consume
    if(jv_get_kind(result) == JV_KIND_NUMBER) { // no consume
      D3("Processing a number");
      *res = (int)jv_number_value(result); // consumed; make it (unsigned int)
      D3("Valid result: %d", *res);
    } else {
      D3("Valid result but not a string, nor a number");
      //jv_dump(result, 0);
      jv_free(result);
    }
  }
  return 0;
}

int
cega_resolve(const char *endpoint,
	     int (*cb)(char*, uid_t, char*, char*, char*))
{
  int rc = 1; /* error */
  struct curl_res_s* cres = NULL;
  jq_state* jq = NULL;
  CURL* curl = NULL;

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
  D2("Parsing the JSON response");
  jv parsed_response = jv_parse(cres->body);

  if (!jv_is_valid(parsed_response)) { D2("Invalid JSON response"); goto BAILOUT; }

  /* Preparing the queries */
  if ((jq = jq_init()) == NULL) { D2("jq memory allocation error"); goto BAILOUT; }

  char *username = NULL;
  char *pwd = NULL;
  char *pbk = NULL;
  char *gecos = NULL;
  int uid = -1;

  rc = 
    json2str(jq, CEGA_JSON_USER , jv_copy(parsed_response), &username ) +
    json2str(jq, CEGA_JSON_PWD  , jv_copy(parsed_response), &pwd      ) +
    json2str(jq, CEGA_JSON_PBK  , jv_copy(parsed_response), &pbk      ) +
    json2int(jq, CEGA_JSON_UID  , jv_copy(parsed_response), &uid      ) +
    json2str(jq, CEGA_JSON_GECOS, jv_copy(parsed_response), &gecos    ) ;

  /* Checking the data */
  if( (!pwd && !pbk) || !gecos || uid <= 0 ){ rc = 1; }
  else { rc = cb(username, (uid_t)(uid + options->uid_shift), pwd, pbk, gecos); }

  /* Cleanup for JV */
  jv_free(parsed_response);

BAILOUT:
  if(cres)free(cres);
  if(jq)jq_teardown(&jq);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return rc;
}
