#ifndef CONN_BLOCK_MGR_H 
#define CONN_BLOCK_MGR_H 

#include <string>

class ConnBlock_MGR {
public:
    ConnBlock_MGR();
    ~ConnBlock_MGR();
    //int Init();
    void AddIP2BlockList(std::string& ip);
    void ClearBlockList();
//private:
//    int fd;
};

#endif 
