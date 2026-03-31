/*
 * openssl/err.h — IDE stub redirect for OpenSSL error API.
 *
 * PURPOSE
 * -------
 * This file exists ONLY to satisfy #include <openssl/err.h> on a Windows
 * development host where the real OpenSSL headers are absent.  All relevant
 * declarations are forwarded from our consolidated ssl.h stub.
 *
 * NOT used during compilation inside the Docker container.
 */

#pragma once

#ifndef OPENSSL_ERR_H_STUB
#define OPENSSL_ERR_H_STUB

/* Pull in the consolidated stub which declares ERR_print_errors_fp(),
 * ERR_clear_error(), ERR_get_error(), etc.                              */
#include "ssl.h"

#endif /* OPENSSL_ERR_H_STUB */