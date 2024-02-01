#include "stdafx.h"
#include "log/log.h"
#include "ASCmdAction.h"
#ifdef __linux__
#include <sys/wait.h>
#endif
using namespace ASCmdAction;

ASCode CASCmdAction::Execute()
{
#ifdef __linux__
	std::string strCmdLine = getBundleAString(this, AS_CMDACTION_KEY_CMDLINE, "");
	if (strcmp(strCmdLine.c_str(),"/etc/init.d/serviceosecsafe restart") == 0)
	{
		printf("exit!!!\n");
		_exit(0);
	}

	if (strCmdLine.empty())
		return ASErr_FAIL;
	LOG_DEBUG("do cmd:%s",strCmdLine.c_str());
	int status = system(strCmdLine.c_str());
	if (status < 0)
	{
		 LOG_ERROR("do cmd error: %s", strerror(errno));
		return ASErr_FAIL;
	}

	if (WIFEXITED(status)) {
		int retcode = WEXITSTATUS(status);
		if (retcode != 0)
		{
			LOG_ERROR("cmd normal termination, but exit status = %d", retcode);  //ȡ��cmdstringִ�н��
		}
		else
		{
			LOG_TRACE("do cmd:%s success",strCmdLine.c_str());
		}

		return retcode == 0 ? true : false;

	} else if (WIFSIGNALED(status)) {
		LOG_ERROR("cmd abnormal termination,signal number =%d",
			WTERMSIG(status));  //���cmdstring���ź��жϣ�ȡ���ź�ֵ
		return ASErr_FAIL;
	} else if (WIFSTOPPED(status)) {
		//���cmdstring���ź���ִͣ�У�ȡ���ź�ֵ
		LOG_ERROR("process stopped, signal number =%d", WSTOPSIG(status));
		return ASErr_FAIL;
	}
	else {
		//���cmdstring���ź���ִͣ�У�ȡ���ź�ֵ
		LOG_ERROR("Unknown Error when do cmd: %s", strCmdLine.c_str());
		return ASErr_FAIL;
	}
#endif
	return ASErr_OK;
	
}