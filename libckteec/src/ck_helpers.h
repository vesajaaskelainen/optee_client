/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef LIBCKTEEC_CK_HELPERS_H
#define LIBCKTEEC_CK_HELPERS_H

#include <pkcs11.h>
#include <stdint.h>
#include <stddef.h>
#include <pkcs11_ta.h>
#include <tee_client_api.h>

#include "local_utils.h"

#ifdef DEBUG
#define ASSERT_CK_RV(_rv, ...)						\
	do {								\
		const CK_RV ref[] = { __VA_ARGS__ };			\
		size_t count = ARRAY_SIZE(ref);				\
									\
		ckteec_assert_expected_rv(__func__, (_rv), ref, count);	\
	} while (0)

void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count);
#else
#define ASSERT_CK_RV(_rv, ...)		(void)0
#endif /*DEBUG*/

/*
 * PKCS11 TA reserves vendor ID 0xffffffff to represent an invalid ID
 * (attribute class, type, ...)
 */
#define CK_VENDOR_INVALID_ID		0xffffffffUL
#define PKCS11_CK_VENDOR_INVALID_ID	0xffffffffUL

int ta_attr2boolprop_shift(CK_ULONG attr);

CK_RV teec2ck_rv(TEEC_Result res);

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t attribute_id);
size_t ck_attr_is_type(uint32_t attribute_id);
int ck_attr2boolprop_shift(CK_ULONG attr);

int ta_object_has_boolprop(uint32_t class);
int ta_class_has_type(uint32_t class);

/*
 * Try to guess key type if mechanism is key generation
 *
 * @mech: Referecn to mechanism
 * @attrs; Reference to input object attributes
 * @count: number of attributes for the object, output value may be incremented
 * @attrs_new_p: Referenece to output attributes, always defines the key type
 *
 * This may be needed because some tools (e.g.: pkcs11-tool) may not specify
 * some attributes as key type when these can be assumed from the mechanism
 * type.
 *
 * The function allocates memory for a copy of the attributes since it could
 * be increased when adding the missing attribute. Caller is responsible from
 * freeing the output attribute references.
 */
CK_RV ck_guess_key_type(CK_MECHANISM_PTR mecha,
		       CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR count,
		       CK_ATTRIBUTE_PTR *attrs_new_p);

#endif /*LIBCKTEEC_CK_HELPERS_H*/
