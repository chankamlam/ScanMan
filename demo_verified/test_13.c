/* test_13.c —— 安全对照：这些函数没有命中
 *
 * 这些函数摘自公开的漏洞数据集（CVEfixes / BigVul / DiverseVul）的**测试划分**，
 * 标签来自原始修复提交，不是本项目的判断。挑选口径：
 * 代码完整、能从字符串抽出恰好一个函数、且模型在阈值下判定与数据集标签一致。
 *
 * 它们的作用是**演示与回归**：保证界面上看到的结果是预期内的。
 * 不能用来衡量模型效果 —— 这是按「模型判对」筛出来的，天然带选择偏差。
 */

GF_Err av1c_box_size(GF_Box *s) {
	u32 i;
	GF_AV1ConfigurationBox *ptr = (GF_AV1ConfigurationBox *)s;

	if (!ptr->config) {
		ptr->size = 0;
		return GF_BAD_PARAM;
	}

	ptr->size += 4;

	for (i = 0; i < gf_list_count(ptr->config->obu_array); ++i) {
		GF_AV1_OBUArrayEntry *a = gf_list_get(ptr->config->obu_array, i);
		ptr->size += a->obu_length;
	}

	return GF_OK;
}

BOOLEAN BTM_GetSecurityFlagsByTransport (BD_ADDR bd_addr, UINT8 * p_sec_flags,
                                                tBT_TRANSPORT transport)
{
    tBTM_SEC_DEV_REC *p_dev_rec;

 if ((p_dev_rec = btm_find_dev (bd_addr)) != NULL)
 {
 if (transport == BT_TRANSPORT_BR_EDR)
 *p_sec_flags = (UINT8) p_dev_rec->sec_flags;
 else
 *p_sec_flags = (UINT8) (p_dev_rec->sec_flags >> 8);

 return(TRUE);
 }
    BTM_TRACE_ERROR ("BTM_GetSecurityFlags false");
 return(FALSE);
}

static const char *cmd_response_body_mime_types_clear(cmd_parms *cmd,
                                                      void *_dcfg)
{
    directory_config *dcfg = (directory_config *)_dcfg;
    if (dcfg == NULL) return NULL;

    dcfg->of_mime_types_cleared = 1;

    if ((dcfg->of_mime_types != NULL)&&(dcfg->of_mime_types != NOT_SET_P)) {
        apr_table_clear(dcfg->of_mime_types);
    }

    return NULL;
}

static int ntop_interface_name2id(lua_State* vm) {
  char *if_name;

  ntop->getTrace()->traceEvent(TRACE_INFO, "%s() called", __FUNCTION__);

  if(ntop_lua_check(vm, __FUNCTION__, 1, LUA_TSTRING)) return(CONST_LUA_ERROR);
  if_name = (char*)lua_tostring(vm, 1);

  lua_pushinteger(vm, ntop->getInterfaceViewIdByName(if_name));

  return(CONST_LUA_OK);
}
