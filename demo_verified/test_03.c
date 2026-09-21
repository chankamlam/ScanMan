/*
 * krb5.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-119） ==== */
bool_t xdr_nullstring(XDR *xdrs, char **objp)
{
     u_int size;

     if (xdrs->x_op == XDR_ENCODE) {
	  if (*objp == NULL)
	       size = 0;
	  else
	       size = strlen(*objp) + 1;
     }
     if (! xdr_u_int(xdrs, &size)) {
	  return FALSE;
	}
     switch (xdrs->x_op) {
     case XDR_DECODE:
	  if (size == 0) {
	       *objp = NULL;
	       return TRUE;
	  } else if (*objp == NULL) {
	       *objp = (char *) mem_alloc(size);
	       if (*objp == NULL) {
		    errno = ENOMEM;
 		    return FALSE;
 	       }
 	  }
	  return (xdr_opaque(xdrs, *objp, size));
 
      case XDR_ENCODE:
 	  if (size != 0)
	       return (xdr_opaque(xdrs, *objp, size));
	  return TRUE;

     case XDR_FREE:
	  if (*objp != NULL)
	       mem_free(*objp, size);
	  *objp = NULL;
	  return TRUE;
     }

     return FALSE;
}
