# dnspod-ddns-php

因办公室没有固定IP，各种第三方动态域名又不稳定，查询 DNSPod 得知有相关修改域名记录的 API，有了用此 API 实现动态域名的想法，测试后，符合需求。

部署使用简单，将配置好的文件直接传至服务器上，使用设备访问配置页面即可修改 DNSPod 的记录。（我们是在办公室使用一个树莓派定时访问页面。）

优点：
- 不依赖第三方动态域名提供商，使用自己的域名，好看；
- 无任何客户端依赖，浏览器访问即可刷新域名记录；
- 稳定。

需要服务器支持 CURL。
