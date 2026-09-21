/*
 * openssl.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-399） ==== */
SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username)
 {
     int i;
     SRP_user_pwd *user;
    unsigned char digv[SHA_DIGEST_LENGTH];
    unsigned char digs[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;
 
     if (vb == NULL)
         return NULL;
     for (i = 0; i < sk_SRP_user_pwd_num(vb->users_pwd); i++) {
         user = sk_SRP_user_pwd_value(vb->users_pwd, i);
         if (strcmp(user->id, username) == 0)
             return user;
     }
     if ((vb->seed_key == NULL) ||
         (vb->default_g == NULL) || (vb->default_N == NULL))
         return NULL;
        if (!(len = t_fromb64(tmp, N)))
            goto err;
        N_bn = BN_bin2bn(tmp, len, NULL);
        if (!(len = t_fromb64(tmp, g)))
            goto err;
        g_bn = BN_bin2bn(tmp, len, NULL);
        defgNid = "*";
    } else {
        SRP_gN *gN = SRP_get_gN_by_id(g, NULL);
        if (gN == NULL)
            goto err;
        N_bn = gN->N;
        g_bn = gN->g;
        defgNid = gN->id;
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
