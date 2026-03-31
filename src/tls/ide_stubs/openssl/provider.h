/*
 * openssl/provider.h — IDE stub redirect for OpenSSL 3.x provider API.
 *
 * PURPOSE
 * -------
 * This file exists ONLY to satisfy #include <openssl/provider.h> on a
 * Windows development host where the real OpenSSL 3.x headers are absent.
 * All relevant declarations (OSSL_PROVIDER, OSSL_PROVIDER_load, etc.) are
 * forwarded from our consolidated ssl.h stub.
 *
 * NOT used during compilation inside the Docker container.
 * The real header lives at /opt/openssl/include/openssl/provider.h.
 */

#pragma once

#ifndef OPENSSL_PROVIDER_H_STUB
#define OPENSSL_PROVIDER_H_STUB

/* Pull in the consolidated stub which declares:
 *   OSSL_PROVIDER         (opaque handle typedef)
 *   OSSL_LIB_CTX          (opaque library context typedef)
 *   OSSL_PROVIDER_load()
 *   OSSL_PROVIDER_unload()
 *   OSSL_PROVIDER_available()
 */
#include "ssl.h"

#endif /* OPENSSL_PROVIDER_H_STUB */