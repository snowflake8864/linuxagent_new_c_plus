# bedrock

---

## makefile 相关

1. makefile可以添加：参数VER（版本号）和参数REVISION（GIT提交记录sha1）；
2. VER和REVISION的信息会连同编译时间和日期一起被打入到compile_info.o的字符信息集中；
3. 后期的ELF文件可以通过引入这个.o文件来接入版本和提交记录；
4. 查看方式：`strings [ELF文件] | grep BUILD_INFO`，演示结果如下：
`BUILD_INFO: 1.0.0.1000 ae1fe2e301886cad4f005c6ff45d438ee8477285 Apr 12 2019 10:05:08`

---

## build.sh 相关