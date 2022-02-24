#贡献指南

##编码规范
代码整体遵循华为C语言编码规范，函数命名采用内核编码风格。

##源码编译
首先查看您是否具有所需的构建依赖项。README中有相应描述，建议配置yum源后安装对应软件包
编译步骤执行一下脚本即可：
```
sh build/build.sh
```


##代码结构
`src` lstack与 ltran源码
`doc` ReleaseNote等文档
`build` 编译工具与脚本
`License` 开源License许可证
