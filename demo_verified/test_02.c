/*
 * jasper.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-119） ==== */
void jpc_qmfb_split_colgrp(jpc_fix_t *a, int numrows, int stride,
  int parity)
{

	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
	jpc_fix_t splitbuf[QMFB_SPLITBUFSIZE * JPC_QMFB_COLGRPSIZE];
	jpc_fix_t *buf = splitbuf;
	jpc_fix_t *srcptr;
	jpc_fix_t *dstptr;
	register jpc_fix_t *srcptr2;
	register jpc_fix_t *dstptr2;
 	register int n;
 	register int i;
 	int m;
	int hstartcol;
 
 	/* Get a buffer. */
 	if (bufsize > QMFB_SPLITBUFSIZE) {
		if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
 			/* We have no choice but to commit suicide in this case. */
 			abort();
 		}
 	}
 
 	if (numrows >= 2) {
		hstartcol = (numrows + 1 - parity) >> 1;
		m = numrows - hstartcol;
 
 		/* Save the samples destined for the highpass channel. */
 		n = m;
		dstptr = buf;
		srcptr = &a[(1 - parity) * stride];
		while (n-- > 0) {
			dstptr2 = dstptr;
			srcptr2 = srcptr;
			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
				*dstptr2 = *srcptr2;
				++dstptr2;
				++srcptr2;
			}
			dstptr += JPC_QMFB_COLGRPSIZE;
			srcptr += stride << 1;
		}
		/* Copy the appropriate samples into the lowpass channel. */
		dstptr = &a[(1 - parity) * stride];
		srcptr = &a[(2 - parity) * stride];
		n = numrows - m - (!parity);
		while (n-- > 0) {
			dstptr2 = dstptr;
			srcptr2 = srcptr;
			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
				*dstptr2 = *srcptr2;
				++dstptr2;
				++srcptr2;
			}
			dstptr += stride;
 			srcptr += stride << 1;
 		}
 		/* Copy the saved samples into the highpass channel. */
		dstptr = &a[hstartcol * stride];
 		srcptr = buf;
 		n = m;
 		while (n-- > 0) {
			dstptr2 = dstptr;
			srcptr2 = srcptr;
			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
				*dstptr2 = *srcptr2;
				++dstptr2;
				++srcptr2;
			}
			dstptr += stride;
			srcptr += JPC_QMFB_COLGRPSIZE;
		}
	}

	/* If the split buffer was allocated on the heap, free this memory. */
	if (buf != splitbuf) {
		jas_free(buf);
	}

}

/* ==== 真实标签：有漏洞（CWE-119） ==== */
void jpc_qmfb_join_colgrp(jpc_fix_t *a, int numrows, int stride,
  int parity)
{

	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
	jpc_fix_t joinbuf[QMFB_JOINBUFSIZE * JPC_QMFB_COLGRPSIZE];
	jpc_fix_t *buf = joinbuf;
	jpc_fix_t *srcptr;
	jpc_fix_t *dstptr;
	register jpc_fix_t *srcptr2;
	register jpc_fix_t *dstptr2;
	register int n;
	register int i;
	int hstartcol;
 
 	/* Allocate memory for the join buffer from the heap. */
 	if (bufsize > QMFB_JOINBUFSIZE) {
		if (!(buf = jas_alloc3(bufsize, JPC_QMFB_COLGRPSIZE, sizeof(jpc_fix_t)))) {
 			/* We have no choice but to commit suicide. */
 			abort();
 		}
	}

	hstartcol = (numrows + 1 - parity) >> 1;

	/* Save the samples from the lowpass channel. */
	n = hstartcol;
	srcptr = &a[0];
	dstptr = buf;
	while (n-- > 0) {
		dstptr2 = dstptr;
		srcptr2 = srcptr;
		for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
			*dstptr2 = *srcptr2;
			++dstptr2;
			++srcptr2;
		}
		srcptr += stride;
		dstptr += JPC_QMFB_COLGRPSIZE;
	}
	/* Copy the samples from the highpass channel into place. */
	srcptr = &a[hstartcol * stride];
	dstptr = &a[(1 - parity) * stride];
	n = numrows - hstartcol;
	while (n-- > 0) {
		dstptr2 = dstptr;
		srcptr2 = srcptr;
		for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
			*dstptr2 = *srcptr2;
			++dstptr2;
			++srcptr2;
		}
		dstptr += 2 * stride;
		srcptr += stride;
	}
	/* Copy the samples from the lowpass channel into place. */
	srcptr = buf;
	dstptr = &a[parity * stride];
	n = hstartcol;
	while (n-- > 0) {
		dstptr2 = dstptr;
		srcptr2 = srcptr;
		for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
			*dstptr2 = *srcptr2;
			++dstptr2;
			++srcptr2;
		}
		dstptr += 2 * stride;
		srcptr += JPC_QMFB_COLGRPSIZE;
	}

	/* If the join buffer was allocated on the heap, free this memory. */
	if (buf != joinbuf) {
		jas_free(buf);
	}

}

/* ==== 真实标签：有漏洞（CWE-119） ==== */
void jpc_qmfb_split_col(jpc_fix_t *a, int numrows, int stride,
  int parity)
{

	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
	jpc_fix_t splitbuf[QMFB_SPLITBUFSIZE];
	jpc_fix_t *buf = splitbuf;
	register jpc_fix_t *srcptr;
 	register jpc_fix_t *dstptr;
 	register int n;
 	register int m;
	int hstartcol;
 
 	/* Get a buffer. */
 	if (bufsize > QMFB_SPLITBUFSIZE) {
		if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
			/* We have no choice but to commit suicide in this case. */
			abort();
		}
 	}
 
 	if (numrows >= 2) {
		hstartcol = (numrows + 1 - parity) >> 1;
		m = numrows - hstartcol;
 
 		/* Save the samples destined for the highpass channel. */
 		n = m;
		dstptr = buf;
		srcptr = &a[(1 - parity) * stride];
		while (n-- > 0) {
			*dstptr = *srcptr;
			++dstptr;
			srcptr += stride << 1;
		}
		/* Copy the appropriate samples into the lowpass channel. */
		dstptr = &a[(1 - parity) * stride];
		srcptr = &a[(2 - parity) * stride];
		n = numrows - m - (!parity);
		while (n-- > 0) {
			*dstptr = *srcptr;
			dstptr += stride;
 			srcptr += stride << 1;
 		}
 		/* Copy the saved samples into the highpass channel. */
		dstptr = &a[hstartcol * stride];
 		srcptr = buf;
 		n = m;
 		while (n-- > 0) {
			*dstptr = *srcptr;
			dstptr += stride;
			++srcptr;
		}
	}

	/* If the split buffer was allocated on the heap, free this memory. */
	if (buf != splitbuf) {
		jas_free(buf);
	}

}
