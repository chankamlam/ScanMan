/*
 * libgit2.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-476） ==== */
static int add_push_report_sideband_pkt(git_push *push, git_pkt_data *data_pkt, git_buf *data_pkt_buf)
{
	git_pkt *pkt;
	const char *line, *line_end;
	size_t line_len;
	int error;
	int reading_from_buf = data_pkt_buf->size > 0;

	if (reading_from_buf) {
		/* We had an existing partial packet, so add the new
		 * packet to the buffer and parse the whole thing */
		git_buf_put(data_pkt_buf, data_pkt->data, data_pkt->len);
		line = data_pkt_buf->ptr;
		line_len = data_pkt_buf->size;
	}
	else {
		line = data_pkt->data;
		line_len = data_pkt->len;
	}

	while (line_len > 0) {
		error = git_pkt_parse_line(&pkt, line, &line_end, line_len);

		if (error == GIT_EBUFS) {
			/* Buffer the data when the inner packet is split
			 * across multiple sideband packets */
			if (!reading_from_buf)
				git_buf_put(data_pkt_buf, line, line_len);
			error = 0;
			goto done;
		}
		else if (error < 0)
			goto done;

		/* Advance in the buffer */
 		line_len -= (line_end - line);
 		line = line_end;
 
		/* When a valid packet with no content has been
		 * read, git_pkt_parse_line does not report an
		 * error, but the pkt pointer has not been set.
		 * Handle this by skipping over empty packets.
		 */
		if (pkt == NULL)
			continue;
 		error = add_push_report_pkt(push, pkt);
 
 		git_pkt_free(pkt);

		if (error < 0 && error != GIT_ITEROVER)
			goto done;
	}

	error = 0;

done:
	if (reading_from_buf)
		git_buf_consume(data_pkt_buf, line_end);
	return error;
}

/* ==== 真实标签：有漏洞（CWE-125） ==== */
int git_delta_apply(
	void **out,
	size_t *out_len,
	const unsigned char *base,
	size_t base_len,
	const unsigned char *delta,
	size_t delta_len)
{
	const unsigned char *delta_end = delta + delta_len;
	size_t base_sz, res_sz, alloc_sz;
	unsigned char *res_dp;

	*out = NULL;
	*out_len = 0;

	/*
	 * Check that the base size matches the data we were given;
	 * if not we would underflow while accessing data from the
	 * base object, resulting in data corruption or segfault.
	 */
	if ((hdr_sz(&base_sz, &delta, delta_end) < 0) || (base_sz != base_len)) {
		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
		return -1;
	}

	if (hdr_sz(&res_sz, &delta, delta_end) < 0) {
		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
		return -1;
	}

	GITERR_CHECK_ALLOC_ADD(&alloc_sz, res_sz, 1);
	res_dp = git__malloc(alloc_sz);
	GITERR_CHECK_ALLOC(res_dp);

	res_dp[res_sz] = '\0';
	*out = res_dp;
	*out_len = res_sz;

	while (delta < delta_end) {
		unsigned char cmd = *delta++;
		if (cmd & 0x80) {
 			/* cmd is a copy instruction; copy from the base. */
 			size_t off = 0, len = 0;
 
			if (cmd & 0x01) off = *delta++;
			if (cmd & 0x02) off |= *delta++ << 8UL;
			if (cmd & 0x04) off |= *delta++ << 16UL;
			if (cmd & 0x08) off |= ((unsigned) *delta++ << 24UL);
			if (cmd & 0x10) len = *delta++;
			if (cmd & 0x20) len |= *delta++ << 8UL;
			if (cmd & 0x40) len |= *delta++ << 16UL;
 			if (!len)       len = 0x10000;
 
 			if (base_len < off + len || res_sz < len)
 				goto fail;
			memcpy(res_dp, base + off, len);
			res_dp += len;
			res_sz -= len;

		} else if (cmd) {
			/*
			 * cmd is a literal insert instruction; copy from
			 * the delta stream itself.
			 */
			if (delta_end - delta < cmd || res_sz < cmd)
				goto fail;
			memcpy(res_dp, delta, cmd);
			delta += cmd;
			res_dp += cmd;
			res_sz -= cmd;

		} else {
			/* cmd == 0 is reserved for future encodings. */
			goto fail;
		}
	}

	if (delta != delta_end || res_sz)
		goto fail;
	return 0;

fail:
	git__free(*out);

	*out = NULL;
	*out_len = 0;

	giterr_set(GITERR_INVALID, "failed to apply delta");
	return -1;
}
