#ifndef KTQ_JS_UTIL_H
#define KTQ_JS_UTIL_H

struct cJSON;

int ktq_json_get_int(int* nval,cJSON* parent,
                    const char* name);
const char* ktq_json_get_str(cJSON* parent,
                        const char* name);

#endif
