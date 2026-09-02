// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2024 Microsoft Corporation. All rights reserved.
 */

#include <linux/cleanup.h>
#include <linux/hex.h>
#include "digest.h"

DEFINE_FREE(ipe_digest_free, struct digest_info *, ipe_digest_free(_T))

/**
 * ipe_digest_parse() - parse a digest in IPE's policy.
 * @valstr: Supplies the string parsed from the policy.
 *
 * Digests in IPE are defined in a standard way:
 *	<alg_name>:<hex>
 *
 * Use this function to create a property to parse the digest
 * consistently. The parsed digest will be saved in @value in IPE's
 * policy.
 *
 * Return: The parsed digest_info structure on success. If an error occurs,
 * the function will return the error value (via ERR_PTR).
 */
struct digest_info *ipe_digest_parse(const char *valstr)
{
	struct digest_info *info __free(ipe_digest_free) = kzalloc_obj(*info);
	char *sep, *raw_digest;
	u8 *digest = NULL;

	if (!info)
		return ERR_PTR(-ENOMEM);

	sep = strchr(valstr, ':');
	if (!sep)
		return ERR_PTR(-EBADMSG);

	info->alg = kstrndup(valstr, sep - valstr, GFP_KERNEL);
	if (!info->alg)
		return ERR_PTR(-ENOMEM);

	raw_digest = sep + 1;
	info->digest_len = (strlen(raw_digest) + 1) / 2;
	digest = kzalloc(info->digest_len, GFP_KERNEL);
	if (!digest)
		return ERR_PTR(-ENOMEM);
	info->digest = digest;

	if (hex2bin(digest, raw_digest, info->digest_len) < 0)
		return ERR_PTR(-EINVAL);

	return_ptr(info);
}

/**
 * ipe_digest_new() - create a digest from raw bytes.
 * @alg: Supplies the digest algorithm name.
 * @digest: Supplies the raw digest bytes.
 * @digest_len: Supplies the number of bytes in @digest.
 *
 * Return: The new digest_info structure on success. If an error occurs,
 * the function will return the error value (via ERR_PTR).
 */
struct digest_info *ipe_digest_new(const char *alg, const u8 *digest,
				   size_t digest_len)
{
	struct digest_info *info __free(ipe_digest_free) = kzalloc_obj(*info);

	if (!info)
		return ERR_PTR(-ENOMEM);

	info->digest = kmemdup(digest, digest_len, GFP_KERNEL);
	if (!info->digest)
		return ERR_PTR(-ENOMEM);

	info->alg = kstrdup(alg, GFP_KERNEL);
	if (!info->alg)
		return ERR_PTR(-ENOMEM);

	info->digest_len = digest_len;

	return_ptr(info);
}

/**
 * ipe_digest_eval() - evaluate an IPE digest against another digest.
 * @expected: Supplies the policy-provided digest value.
 * @digest: Supplies the digest to compare against the policy digest value.
 *
 * Return:
 * * %true	- digests match
 * * %false	- digests do not match
 */
bool ipe_digest_eval(const struct digest_info *expected,
		     const struct digest_info *digest)
{
	return (expected->digest_len == digest->digest_len) &&
	       (!strcmp(expected->alg, digest->alg)) &&
	       (!memcmp(expected->digest, digest->digest, expected->digest_len));
}

/**
 * ipe_digest_free() - free an IPE digest.
 * @info: Supplies a pointer the policy-provided digest to free.
 */
void ipe_digest_free(struct digest_info *info)
{
	if (IS_ERR_OR_NULL(info))
		return;

	kfree(info->alg);
	kfree(info->digest);
	kfree(info);
}

/**
 * ipe_digest_audit() - audit a digest that was sourced from IPE's policy.
 * @ab: Supplies the audit_buffer to append the formatted result.
 * @info: Supplies a pointer to source the audit record from.
 *
 * Digests in IPE are audited in this format:
 *	<alg_name>:<hex>
 */
void ipe_digest_audit(struct audit_buffer *ab, const struct digest_info *info)
{
	audit_log_untrustedstring(ab, info->alg);
	audit_log_format(ab, ":");
	audit_log_n_hex(ab, info->digest, info->digest_len);
}
