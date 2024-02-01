#ifndef __LABEL_MGR_H__
#define __LABEL_MGR_H__

class ISocketClientMgr;

class LabelMgr
{
public:
    LabelMgr();
    ~LabelMgr();

    int Init();
    int InitLog();
};

#endif
