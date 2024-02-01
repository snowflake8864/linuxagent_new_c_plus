## Skylar kernel module
### Note
* 天擎Linux客户端内核模块2.0版本;该内核模块实现了自保,文件实时防护，审计，密标，多网隔离，水印，设备管控等功能
* 从2.2版本开始，驱动名称由tq_base修改为qax_tq_base
* 本内核模块同时支持netlink与character device两种通信模式
* 本内核模块要求与其通信的应用层进程必须具备root用户权限
* 本内核模块针对银河Kylin 4.0.2 (ARM64 4.13-20170224.kylin.5.server)必须在ARM64 Ubuntu 16.04上编译，否则会出现即使模块引用记数为0,仍然会无法正常卸载的问题;其原因是模块的exit函数指针被异常设置成空了，但具体原因未找到。
* 单独对内核开启debug: 内核模块导出了/sys/qax/debug接口文件用于开启debug,可以使用 echo -n 1 > /sys/qax/debug 来开启debug日志;也可以通过将debug的值设置为0来关闭内核debug日志;此处要想修改/sys/qax/debug文件，必须切到root用户;sudo方式下是不行的
* 从2.0.0.2000版本开始，引入了white-box test工作模式，该模式下内核模块不验证用户态程序名称，可以很方便的进行测试及调式;可以通过echo -n "whiteboxtest" >/sys/qax/run_mode直接开启(同样需要在root用户下操作)
  
### 代码目录结构
* abnormal          -->内核加载异常逻辑
* av		    -->杀毒文件实时防护
* audit             -->审计功能
* cdev              -->字符通信功能
* core              -->通信管控，策略分发逻辑
* defense           -->自保功能
* device_control    -->设备管控
* fs                -->文件系统Hook逻辑
* hook              -->syscall hookl逻辑
* kthread           -->审计功能内核线程逻辑
* nac_water         -->水印
* netlink           -->netlink通信功能
* network_isolate   -->多网切换
* notify            -->客户端通知管控逻辑
* utils             -->公共工具
* hookframe			-->hook框架submodule目录,该目录是引用的名为kernel/feature/hook_frame的框架分支代码

### 编译

* make                        -->编译出名为qax_tq_base的内核模块(从2.2版本开始驱动名称由tq_base调整为qax_tq_base)
* make NAME=<指定内核模块名>  -->编译出<指定名称的内核模块>,比如密标是: make NAME=QAXMJBZKO1
* make ZYJ_AUDIT=1            -->编译出专用机主审的相关功能，编译出的驱动名称会更改为: tq_zyj_audit;sysfs根路径会自动修改为/sys/qaxzyjaudit
