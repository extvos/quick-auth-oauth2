# quick-builtin-oauth2

在`quick-auth-base`的基础上，提供基于`OAuth2`标准的第三方登录支持。目前支持微信登录以及标准的OAuth2登录。



## 微信登录配置

```ini
quick.auth.wechat.app-id=xxxx
quick.auth.wechat.app-secret=xxxx
```



## 标准OAuth2登录配置

```ini
quick.auth.oauth2.endpoint=http://xxxx
quick.auth.oauth2.client-id=xxx
quick.auth.oauth2.secret=xxx
quick.auth.oauth2.scope=xxx
```



## 扩展新的登录方式

增加新的登录方式支持，可以通过注入Bean的方式实现。 注入实现了接口`org.extvos.auth.service.OAuthProvider`的Bean，系统即可获取和使用到该登录方式。

```java
public interface OAuthProvider {

    /**
     * A unique identifier for service provider
     *
     * @return string of slug
     */
    String getSlug();

    /**
     * get provider name
     * @return name as String
     */
    String getName();

    /**
     * get if provider support in page redirect.
     * @return true if supported
     */
    default boolean redirectSupported(){ return false; };

    /**
     * get code url for generate QrCode or redirect user browser
     *
     * @param state a string to identify state of code url
     * @param redirectUri a string to give the redirectUri
     * @return a string of url.
     * @throws RestletException if errors
     */
    String getCodeUrl(String state,String redirectUri) throws RestletException;


    /**
     * Get access token info via code
     * @param code code returned by provider
     * @return map with results.
     * @throws RestletException when errors
     */
    Map<String,Object> getAccessToken(String code) throws RestletException;
}
```





## 接口列表

### 第三方登录持列表


**接口地址**:`/auth/oauth2/providers`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


**请求参数**:


暂无


**响应状态**:


| 状态码 | 说明         | schema                      |
| ------ | ------------ | --------------------------- |
| 200    | OK           | Result«List«OAuthProvider»» |
| 401    | Unauthorized |                             |
| 403    | Forbidden    |                             |
| 404    | Not Found    |                             |


**响应参数**:


| 参数名称         | 参数说明 | 类型           | schema         |
| ---------------- | -------- | -------------- | -------------- |
| code             |          | integer(int32) | integer(int32) |
| count            |          | integer(int64) | integer(int64) |
| data             |          | array          | OAuthProvider  |
| &emsp;&emsp;name |          | string         |                |
| &emsp;&emsp;slug |          | string         |                |
| error            |          | string         |                |
| msg              |          | string         |                |
| page             |          | integer(int64) | integer(int64) |
| pageSize         |          | integer(int64) | integer(int64) |
| total            |          | integer(int64) | integer(int64) |


**响应示例**:
```javascript
{
	"code": 0,
	"count": 0,
	"data": [
		{
			"name": "",
			"slug": ""
		}
	],
	"error": "",
	"msg": "",
	"page": 0,
	"pageSize": 0,
	"total": 0
}
```



### 第三方登录跳转URL


**接口地址**:`/auth/oauth2/{provider}/code-url`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


**请求参数**:


| 参数名称    | 参数说明    | 请求类型 | 是否必须 | 数据类型 | schema |
| ----------- | ----------- | -------- | -------- | -------- | ------ |
| provider    | provider    | path     | true     | string   |        |
| redirectUri | redirectUri | query    | false    | string   |        |


**响应状态**:


| 状态码 | 说明         | schema         |
| ------ | ------------ | -------------- |
| 200    | OK           | Result«string» |
| 401    | Unauthorized |                |
| 403    | Forbidden    |                |
| 404    | Not Found    |                |


**响应参数**:


| 参数名称 | 参数说明 | 类型           | schema         |
| -------- | -------- | -------------- | -------------- |
| code     |          | integer(int32) | integer(int32) |
| count    |          | integer(int64) | integer(int64) |
| data     |          | string         |                |
| error    |          | string         |                |
| msg      |          | string         |                |
| page     |          | integer(int64) | integer(int64) |
| pageSize |          | integer(int64) | integer(int64) |
| total    |          | integer(int64) | integer(int64) |


**响应示例**:
```javascript
{
	"code": 0,
	"count": 0,
	"data": "",
	"error": "",
	"msg": "",
	"page": 0,
	"pageSize": 0,
	"total": 0
}
```

### 第三方登录跳转QRCODE


**接口地址**:`/auth/oauth2/{provider}/code-img`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`image/png`


**接口描述**:<p>获取图片QRCODE，直接输出图片</p>



**请求参数**:


**请求参数**:


| 参数名称    | 参数说明    | 请求类型 | 是否必须 | 数据类型       | schema |
| ----------- | ----------- | -------- | -------- | -------------- | ------ |
| provider    | provider    | path     | true     | string         |        |
| redirectUri | redirectUri | query    | false    | string         |        |
| size        | size        | query    | false    | integer(int32) |        |


**响应状态**:


| 状态码 | 说明         | schema       |
| ------ | ------------ | ------------ |
| 200    | OK           | ModelAndView |
| 401    | Unauthorized |              |
| 403    | Forbidden    |              |
| 404    | Not Found    |              |


**响应参数**:

`png`格式的Qr-Code图片


### 跳转第三方登录URL


**接口地址**:`/auth/oauth2/{provider}/login-redirect`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


**请求参数**:


| 参数名称    | 参数说明    | 请求类型 | 是否必须 | 数据类型 | schema |
| ----------- | ----------- | -------- | -------- | -------- | ------ |
| provider    | provider    | path     | true     | string   |        |
| failureUri  | failureUri  | query    | false    | string   |        |
| redirectUri | redirectUri | query    | false    | string   |        |
| state       | state       | query    | false    | string   |        |


**响应状态**:


| 状态码 | 说明         | schema         |
| ------ | ------------ | -------------- |
| 200    | OK           | Result«object» |
| 401    | Unauthorized |                |
| 403    | Forbidden    |                |
| 404    | Not Found    |                |


**响应参数**:


| 参数名称 | 参数说明 | 类型           | schema         |
| -------- | -------- | -------------- | -------------- |
| code     |          | integer(int32) | integer(int32) |
| count    |          | integer(int64) | integer(int64) |
| data     |          | object         |                |
| error    |          | string         |                |
| msg      |          | string         |                |
| page     |          | integer(int64) | integer(int64) |
| pageSize |          | integer(int64) | integer(int64) |
| total    |          | integer(int64) | integer(int64) |


**响应示例**:
```javascript
{
	"code": 0,
	"count": 0,
	"data": {},
	"error": "",
	"msg": "",
	"page": 0,
	"pageSize": 0,
	"total": 0
}
```

### 第三方登录状态


**接口地址**:`/auth/oauth2/{provider}/auth-refresh`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


**请求参数**:


| 参数名称 | 参数说明 | 请求类型 | 是否必须 | 数据类型 | schema |
| -------- | -------- | -------- | -------- | -------- | ------ |
| provider | provider | path     | true     | string   |        |


**响应状态**:


| 状态码 | 说明         | schema              |
| ------ | ------------ | ------------------- |
| 200    | OK           | Result«OAuthResult» |
| 401    | Unauthorized |                     |
| 403    | Forbidden    |                     |
| 404    | Not Found    |                     |


**响应参数**:


| 参数名称             | 参数说明 | 类型           | schema         |
| -------------------- | -------- | -------------- | -------------- |
| code                 |          | integer(int32) | integer(int32) |
| count                |          | integer(int64) | integer(int64) |
| data                 |          | OAuthResult    | OAuthResult    |
| &emsp;&emsp;openId   |          | string         |                |
| &emsp;&emsp;session  |          | string         |                |
| &emsp;&emsp;status   |          | integer(int32) |                |
| &emsp;&emsp;username |          | string         |                |
| error                |          | string         |                |
| msg                  |          | string         |                |
| page                 |          | integer(int64) | integer(int64) |
| pageSize             |          | integer(int64) | integer(int64) |
| total                |          | integer(int64) | integer(int64) |


**响应示例**:
```javascript
{
	"code": 0,
	"count": 0,
	"data": {
		"openId": "",
		"session": "",
		"status": 0,
		"username": ""
	},
	"error": "",
	"msg": "",
	"page": 0,
	"pageSize": 0,
	"total": 0
}
```

### 第三方登录回调


**接口地址**:`/auth/oauth2/{provider}/authorized`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


**请求参数**:


| 参数名称 | 参数说明 | 请求类型 | 是否必须 | 数据类型 | schema |
| -------- | -------- | -------- | -------- | -------- | ------ |
| code     | code     | query    | true     | string   |        |
| provider | provider | path     | true     | string   |        |
| state    | state    | query    | true     | string   |        |


**响应状态**:


| 状态码 | 说明         | schema              |
| ------ | ------------ | ------------------- |
| 200    | OK           | Result«OAuthResult» |
| 401    | Unauthorized |                     |
| 403    | Forbidden    |                     |
| 404    | Not Found    |                     |


**响应参数**:


| 参数名称             | 参数说明 | 类型           | schema         |
| -------------------- | -------- | -------------- | -------------- |
| code                 |          | integer(int32) | integer(int32) |
| count                |          | integer(int64) | integer(int64) |
| data                 |          | OAuthResult    | OAuthResult    |
| &emsp;&emsp;openId   |          | string         |                |
| &emsp;&emsp;session  |          | string         |                |
| &emsp;&emsp;status   |          | integer(int32) |                |
| &emsp;&emsp;username |          | string         |                |
| error                |          | string         |                |
| msg                  |          | string         |                |
| page                 |          | integer(int64) | integer(int64) |
| pageSize             |          | integer(int64) | integer(int64) |
| total                |          | integer(int64) | integer(int64) |


**响应示例**:
```javascript
{
	"code": 0,
	"count": 0,
	"data": {
		"openId": "",
		"session": "",
		"status": 0,
		"username": ""
	},
	"error": "",
	"msg": "",
	"page": 0,
	"pageSize": 0,
	"total": 0
}
```
