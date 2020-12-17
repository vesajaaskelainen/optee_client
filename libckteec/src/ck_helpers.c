// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <ck_debug.h>
#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>

#include "ck_helpers.h"
#include "local_utils.h"

#ifdef DEBUG
void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count)
{
	size_t n = 0;

	for (n = 0; n < expected_count; n++)
		if (rv == expected_rv[n])
			return;

	fprintf(stderr, "libckteec: %s: unexpected return value 0x%lx (%s)\n",
		function, rv, ckr2str(rv));

	assert(0);
}
#endif

CK_RV teec2ck_rv(TEEC_Result res)
{
	switch (res) {
	case TEEC_SUCCESS:
		return CKR_OK;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	case TEEC_ERROR_BAD_PARAMETERS:
		return CKR_ARGUMENTS_BAD;
	case TEEC_ERROR_SHORT_BUFFER:
		return CKR_BUFFER_TOO_SMALL;
	default:
		return CKR_FUNCTION_FAILED;
	}
}

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t id)
{
	if (id == CKA_CLASS)
		return sizeof(CK_ULONG);
	else
		return 0;
}

size_t ck_attr_is_type(uint32_t id)
{
	switch (id) {
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
	case CKA_KEY_GEN_MECHANISM:
		return sizeof(CK_ULONG);
	default:
		return 0;
	}
}

int ta_object_has_boolprop(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_DOMAIN_PARAMETERS:
		return 1;
	default:
		return 0;
	}
}

int ta_class_has_type(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_MECHANISM:
	case PKCS11_CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}

CK_RV ck_guess_key_type(CK_MECHANISM_PTR mecha,
			CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR count,
			CK_ATTRIBUTE_PTR *attrs_new_p)
{
	size_t n;
	CK_ULONG count_new = *count;
	CK_ATTRIBUTE_PTR attrs_new = NULL;
	CK_KEY_TYPE_PTR key_type_p = NULL;
	int key_type_present = 0;
	CK_RV rv;

	for (n = 0; n < *count; n++) {
		if (attrs[n].type == CKA_KEY_TYPE) {
			key_type_present = 1;
			break;
		}
	}
	if (!key_type_present)
		count_new++;

	attrs_new = malloc(count_new * sizeof(CK_ATTRIBUTE));
	if (attrs_new == NULL)
		return CKR_HOST_MEMORY;

	memcpy(attrs_new, attrs, (*count) * sizeof(CK_ATTRIBUTE));

	if (key_type_present) {
		rv = CKR_OK;
		goto bail;
	}

	key_type_p = malloc(sizeof(CK_KEY_TYPE));
	if (key_type_p == NULL) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	switch (mecha->mechanism) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		*key_type_p = CKK_RSA;
		attrs_new[count_new - 1].type = CKA_KEY_TYPE;
		attrs_new[count_new - 1].pValue = key_type_p;
		attrs_new[count_new - 1].ulValueLen = sizeof(CK_KEY_TYPE);
		rv = CKR_OK;
		break;
	case CKM_EC_KEY_PAIR_GEN:
		*key_type_p = CKK_EC;
		attrs_new[count_new - 1].type = CKA_KEY_TYPE;
		attrs_new[count_new - 1].pValue = key_type_p;
		attrs_new[count_new - 1].ulValueLen = sizeof(CK_KEY_TYPE);
		rv = CKR_OK;
		break;
	default:
		rv = CKR_TEMPLATE_INCOMPLETE;
		break;
	}

bail:
	if (rv == CKR_OK) {
		*attrs_new_p = attrs_new;
		*count = count_new;
	} else {
		if (attrs_new)
			free(attrs_new);
		if (key_type_p)
			free(key_type_p);
	}

	return rv;
}
