#include "config.h"

#include "pipeline/iface.h"
#include "pipeline/aes/aes.h"
#include "pipeline/auth_password/auth_password.h"
#include "pipeline/http/http.h"
#include "pipeline/xor/xor.h"

const struct pipeline_ops *SERVER_PIPELINE_OPS_ARR[] = {
    &LAYER_HTTP_OPS,
    &LAYER_AES_OPS,
    &LAYER_XOR_OPS,
    &LAYER_PASSWORD_AUTH_OPS,
    NULL
};