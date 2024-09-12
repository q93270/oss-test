
> 注：当前项目为 Serverless Devs 应用，由于应用中会存在需要初始化才可运行的变量（例如应用部署地区、函数名等等），所以**不推荐**直接 Clone 本仓库到本地进行部署或直接复制 s.yaml 使用，**强烈推荐**通过 `s init ${模版名称}` 的方法或应用中心进行初始化，详情可参考[部署 & 体验](#部署--体验) 。

# oss-upload-presigned-url-app 帮助文档
<p align="center" class="flex justify-center">
    <a href="https://www.serverless-devs.com" class="ml-1">
    <img src="http://editor.devsapp.cn/icon?package=oss-upload-presigned-url-app&type=packageType">
  </a>
  <a href="http://www.devsapp.cn/details.html?name=oss-upload-presigned-url-app" class="ml-1">
    <img src="http://editor.devsapp.cn/icon?package=oss-upload-presigned-url-app&type=packageVersion">
  </a>
  <a href="http://www.devsapp.cn/details.html?name=oss-upload-presigned-url-app" class="ml-1">
    <img src="http://editor.devsapp.cn/icon?package=oss-upload-presigned-url-app&type=packageDownload">
  </a>
</p>

<description>

服务端通过Post签名和Post Policy授权客户端上传文件到OSS的过程

</description>

<codeUrl>



</codeUrl>
<preview>



</preview>


## 前期准备

使用该项目，您需要有开通以下服务并拥有对应权限：

<service>



| 服务/业务 |  权限  |
| --- |  --- |
| 函数计算 |  AliyunFCFullAccess |

</service>

<remark>



</remark>

<disclaimers>



</disclaimers>

## 部署 & 体验

<appcenter>
   
- :fire: 通过 [Serverless 应用中心](https://fcnext.console.aliyun.com/applications/create?template=oss-upload-presigned-url-app) ，
  [![Deploy with Severless Devs](https://img.alicdn.com/imgextra/i1/O1CN01w5RFbX1v45s8TIXPz_!!6000000006118-55-tps-95-28.svg)](https://fcnext.console.aliyun.com/applications/create?template=oss-upload-presigned-url-app) 该应用。
   
</appcenter>
<deploy>
    
- 通过 [Serverless Devs Cli](https://www.serverless-devs.com/serverless-devs/install) 进行部署：
  - [安装 Serverless Devs Cli 开发者工具](https://www.serverless-devs.com/serverless-devs/install) ，并进行[授权信息配置](https://docs.serverless-devs.com/fc/config) ；
  - 初始化项目：`s init oss-upload-presigned-url-app -d oss-upload-presigned-url-app`
  - 进入项目，并进行项目部署：`cd oss-upload-presigned-url-app && s deploy -y`
   
</deploy>

## 应用详情

<appdetail id="flushContent">

## 前期准备

使用该项目，您需要有开通以下服务：
<service>

| 服务 |  备注  |
| --- |  --- |
| 函数计算 FC |  unzip解压函数部署在函数计算 |
| 对象存储 OSS |  待解压的zip文件和解压后的文件存放在对象存储 |

</service>

## 应用详情
服务端通过STS临时访问凭证授权客户端上传文件到OSS的过程如下。
![](https://help-static-aliyun-doc.aliyuncs.com/assets/img/zh-CN/8560603071/e1a4f478cfchc.svg)
1. 客户端向业务服务器请求临时访问凭证。
2. 业务服务器使用STS SDK调用AssumeRole接口，获取临时访问凭证。
3. STS生成并返回临时访问凭证给业务服务器。
4. 业务服务器返回临时访问凭证给客户端。
5. 客户端使用OSS SDK通过该临时访问凭证上传文件到OSS。
6. OSS返回成功响应给客户端。


</appdetail>

## 使用文档

<usedetail id="flushContent">
</usedetail>


<devgroup>


## 开发者社区

您如果有关于错误的反馈或者未来的期待，您可以在 [Serverless Devs repo Issues](https://github.com/serverless-devs/serverless-devs/issues) 中进行反馈和交流。如果您想要加入我们的讨论组或者了解 FC 组件的最新动态，您可以通过以下渠道进行：

<p align="center">  

| <img src="https://serverless-article-picture.oss-cn-hangzhou.aliyuncs.com/1635407298906_20211028074819117230.png" width="130px" > | <img src="https://serverless-article-picture.oss-cn-hangzhou.aliyuncs.com/1635407044136_20211028074404326599.png" width="130px" > | <img src="https://serverless-article-picture.oss-cn-hangzhou.aliyuncs.com/1635407252200_20211028074732517533.png" width="130px" > |
| --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| <center>微信公众号：`serverless`</center>                                                                                         | <center>微信小助手：`xiaojiangwh`</center>                                                                                        | <center>钉钉交流群：`33947367`</center>                                                                                           |
</p>
</devgroup>
