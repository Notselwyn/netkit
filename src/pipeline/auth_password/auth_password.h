#ifndef PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H
#define PIPELINE__AUTH_PASSWORD__AUTH_PASSWORD_H

#include <linux/types.h>

#include "../iface.h"

void sha256(const u8 *data, unsigned int len, u8 *out);


extern const struct pipeline_ops LAYER_PASSWORD_AUTH_OPS;

#endif