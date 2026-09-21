/*
 * curl.c —— 真实项目代码样本
 *
 * 来源：漏洞检测数据集的【测试集】，模型训练时未见过这些函数。
 * 每条函数上方的注释标注了它在数据集里的真实标签；
 * 注释位于函数体外，不会被抽进模型输入。
 */


/* ==== 真实标签：安全 ==== */
CURLcode pop3_regular_transfer(struct connectdata *conn,
                              bool *dophase_done)
{
  CURLcode result=CURLE_OK;
  bool connected=FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = pop3_perform(conn,
                        &connected, /* have we connected after PASV/PORT */
                        dophase_done); /* all commands in the DO-phase done? */

  if(CURLE_OK == result) {

    if(!*dophase_done)
      /* the DO phase has not completed yet */
      return CURLE_OK;

    result = pop3_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}
