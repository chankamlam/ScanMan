/*
 * openssl.c —— 取自真实项目的样本
 * 来源：训练数据的【测试集】，模型训练时没见过。
 * 注释里的真实标签用于对比模型预测；注释在函数体外，不进模型输入。
 */


/* ==== 真实标签：安全 ==== */
int CRYPTO_get_new_dynlockid(void)
	{
	int i = 0;
	CRYPTO_dynlock *pointer = NULL;

	if (dynlock_create_callback == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK);
		return(0);
		}
	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
	if ((dyn_locks == NULL)
		&& ((dyn_locks=sk_CRYPTO_dynlock_new_null()) == NULL))
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	pointer = (CRYPTO_dynlock *)OPENSSL_malloc(sizeof(CRYPTO_dynlock));
	if (pointer == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	pointer->references = 1;
	pointer->data = dynlock_create_callback(__FILE__,__LINE__);
	if (pointer->data == NULL)
		{
		OPENSSL_free(pointer);
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
	/* First, try to find an existing empty slot */
	i=sk_CRYPTO_dynlock_find(dyn_locks,NULL);
	/* If there was none, push, thereby creating a new one */
	if (i == -1)
		/* Since sk_push() returns the number of items on the
		   stack, not the location of the pushed item, we need
		   to transform the returned number into a position,
		   by decreasing it.  */
		i=sk_CRYPTO_dynlock_push(dyn_locks,pointer) - 1;
	else
		/* If we found a place with a NULL pointer, put our pointer
		   in it.  */
		(void)sk_CRYPTO_dynlock_set(dyn_locks,i,pointer);
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (i == -1)
		{
		dynlock_destroy_callback(pointer->data,__FILE__,__LINE__);
		OPENSSL_free(pointer);
		}
	else
		i += 1; /* to avoid 0 */
	return -i;
	}

/* ==== 真实标签：有漏洞（CWE-190） ==== */
static int ssl_scan_clienthello_custom_tlsext(SSL *s,
                                              const unsigned char *data,
                                              const unsigned char *limit,
                                              int *al)
{
    unsigned short type, size, len;
    /* If resumed session or no custom extensions nothing to do */
     if (s->hit || s->cert->srv_ext.meths_count == 0)
         return 1;
 
    if (data >= limit - 2)
         return 1;
     n2s(data, len);
 
    if (data > limit - len)
         return 1;
 
    while (data <= limit - 4) {
         n2s(data, type);
         n2s(data, size);
 
        if (data + size > limit)
             return 1;
         if (custom_ext_parse(s, 1 /* server */ , type, data, size, al) <= 0)
             return 0;

        data += size;
    }

    return 1;
}

/* ==== 真实标签：有漏洞（CWE-189） ==== */
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int i, j, bl;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (ctx->cipher->do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
     bl = ctx->cipher->block_size;
     OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
     if (i != 0) {
        if (i + inl < bl) {
             memcpy(&(ctx->buf[i]), in, inl);
             ctx->buf_len += inl;
             *outl = 0;
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            if (!ctx->cipher->do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            inl -= j;
            in += j;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!ctx->cipher->do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

/* ==== 真实标签：安全 ==== */
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                        EC_POINT *point, const BIGNUM *x,
                                        const BIGNUM *y, BN_CTX *ctx)
{
    if (group->meth->point_set_affine_coordinates == 0) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (!group->meth->point_set_affine_coordinates(group, point, x, y, ctx))
        return 0;

    if (EC_POINT_is_on_curve(group, point, ctx) <= 0) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
              EC_R_POINT_IS_NOT_ON_CURVE);
        return 0;
    }
    return 1;
}
