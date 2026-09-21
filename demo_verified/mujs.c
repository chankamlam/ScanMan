/*
 * mujs.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-119） ==== */
static void ctrycatchfinally(JF, js_Ast *trystm, js_Ast *catchvar, js_Ast *catchstm, js_Ast *finallystm)
{
	int L1, L2, L3;
	L1 = emitjump(J, F, OP_TRY);
	{
		/* if we get here, we have caught an exception in the try block */
		L2 = emitjump(J, F, OP_TRY);
		{
			/* if we get here, we have caught an exception in the catch block */
			cstm(J, F, finallystm); /* inline finally block */
			emit(J, F, OP_THROW); /* rethrow exception */
		}
		label(J, F, L2);
		if (F->strict) {
			checkfutureword(J, F, catchvar);
			if (!strcmp(catchvar->string, "arguments"))
				jsC_error(J, catchvar, "redefining 'arguments' is not allowed in strict mode");
			if (!strcmp(catchvar->string, "eval"))
				jsC_error(J, catchvar, "redefining 'eval' is not allowed in strict mode");
		}
		emitline(J, F, catchvar);
 		emitstring(J, F, OP_CATCH, catchvar->string);
 		cstm(J, F, catchstm);
 		emit(J, F, OP_ENDCATCH);
 		L3 = emitjump(J, F, OP_JUMP); /* skip past the try block to the finally block */
 	}
 	label(J, F, L1);
	cstm(J, F, trystm);
	emit(J, F, OP_ENDTRY);
	label(J, F, L3);
	cstm(J, F, finallystm);
}
