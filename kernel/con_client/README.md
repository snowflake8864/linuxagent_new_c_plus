## sky kernel client
#### Code Note
* test.cpp      -->用于测试内核模块功能的单元测试用例
* secdoctest.c  -->用于测试sec_doc内核功能模块的单元代码，需要与test.cpps配合使用
### Compile
* make              -->编译sky kernel通信so文件libcon_client.so,这种编译出来的不支持字符设备通信
* make OSECMJBZ=1 DRIVER_NAME=OSECMJBZKO1    -->编译支持字符设备功能的sky kernel通信so文件libcon_client.so,且将需要加载的内核模块名指定为OSECMJBZKO1
* make ZYJ_AUDIT=1 DRIVER_NAME=osecs_zyj_audit -->编译出支持专用机主审的通信so文件libcon_client.so,且将需要加载的内核模块名指定为osecs_zyj_audit
* make TEST=1 test_kern  -->单独编译test_kern单元测试程序,用于直接测试内核模块功能;该单元测试用例程序只依赖gnHead.h头文件与netlink_func,epoll_func几个文件，可以单独编译，不需要依赖于common/dependlibs.另外，该用例如果要测试cdev的功能，需要先加载内核模块，然后使用mknod手动创建cdev通信的字符设备文件/dev/ktqdev
* make secdoctest   -->编译用于测试sec_doc内核功能模块单元测试用例secdoctest,需要与test_kern配合使用
* make TEST=1 test_client -->编译test_client单元测试程序;用于测试加载libcon_test.so后整个skylar kernel的功能。这个测试用例无法单独运行需要信赖于libcon_client.so
* make TEST=1 test_av -->单独编译test_av单元测试程序,用于直接测试内核模块功能;该单元测试用例程序只依赖gnHead.h头文件与netlink_func,epoll_func几个文件，可以单独编译，不需要依赖于common/dependlibs.

#### Use Note
* 单元测试用例程序都需要将内核模块中ECHO初始化操作中的进程名验证逻辑从代码上临时关闭，不然无法验证通过导致测试用例无法正常运行
```C
    static int do_echo_set_cmd(u32 portid)
    {
        int nlen = 0;
        int rc = -EINVAL;
        char str[0x100] = {0};
        pid_t pid = CURRENT_PID;

        // if (strcmp(CURRENT_COMM, user_service_path)) 
        // {
        //    LOG_ERROR("bad echo set cmd from %s,portid: %u\n",
        //        CURRENT_COMM,portid);
        //    return rc;
        // }

        LOG_INFO("set portid[%u], pid:%d\n",portid,pid);

        set_portid_service_pid(portid,pid);
        kosecs_hold_ctrl(1); //开启hold

        nlen = snprintf(str,sizeof(str),"%s%s",
                        ECHO_CMD_STR_SET_PORT_ID,
                        SUPPORT_DRIVER_VERSION);

        rc = send_nl_data(NL_POLICY_CMD_ECHO,
                        (void *)str,
                        nlen);
        return rc;
    }
```
* test_kern默认情况下采用的是从/sys/osec/proto中读取的netlink通信id,不需要cdev时的运行方式如下:
```shell
	sudo ./test_kern
```

* test_kern测试用例可以同时用于测试netlink与cdev两种通信模式;测试cdev时，需要先将内核模块insmod到内核中；然后通过mknod命令创建字符设备通信文件/dev/ktqdev；并在执行test_kern时，指定cdev命令行参数才能使用:
```shell
    #cdev_name参数指明字符设备名称,内核模块中设置的默认名称是gnHead.h中指定的: osecmjbz1
    sudo insmod osec_osecs_base.ko.xxxx cdev_name=ktqdev
    #250是主设备号，需要从/proc/devices中查找ktqdev对应的值
    sudo mknod -m 0640 /dev/ktqdev c 250 0
    #此处需要使用root权限，因为我们在内核模块中限定了只能与root用户所有的程序通信
    #/dev/ktqdev是字符设备的完整路径
    sudo ./test_kern cdev /dev/ktqdev
```

* 关于运行时日志: IKernelConnector接口函数SetConfFile用于指定配置文件路径，对于con_client模块而言，目前只有运行时日志用到了配置文件,其格式可以参考con_client.conf文件
* 另外从2.0.0.2000版本引入"白盒测试模式“,该模式下不验证用户态的进程名;以方便进行白盒测试;可以在con_client.conf中加入WHITEBOX=1开启
* 2.0.0.2000版本将默认驱动名称更改为osec_osecs_base

* 从2.0.0.2000版本中引入内核模块名检验，内核模块名需要满足规则: 
```
${modKoName}_<发行版本禁止包含下划线>_<cpu架构(x86|amd64|arm64|mips64|sw64)>_<完整内核版本>
```
