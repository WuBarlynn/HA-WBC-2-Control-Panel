# 局域网版开机卡 (HA-WBC-2) API 文档

## 简介
使用 http 协议访问

## 登录
- **请求方式**: `POST`
- **请求头**: `Content-Type: application/x-www-form-urlencoded;`
- **请求地址**: `http://[设备IP]/api/login`
- **表单字段**: WiFi 密码: `password`

**响应数据**:
```json
{
  "status": "ok",
  //token
  "tK": "1ffa46681a5484975eed1ca48ad130d5" 
}
```

## 连接状态
- **请求方式**: `GET`
- **是否认证**: 否
- **请求地址**: `http://[设备IP]/api/getConnectStatus`

**响应数据**:
```json
{
  "status": "ok",
  // WiFi 账号密码是否正确
  "pE": false,
  // 是否联网
  "oL": true,
  // 是否已经配网
  "wP": true,
  // 固件版本
  "fV": "1.0.1",
  // 局域网IP
  "wI": "10.10.0.139"
}
```

## 设备状态
- **请求方式**: `GET`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/getDeviceState?lang=zh`
- **查询参数**: 语言: `lang`，中文使用 `zh`

**响应数据**:
```json
{
  "status": "ok",
  // 设备温度（摄氏度）
  "tP": 29,
  // 主机开机状态
  "pW": true,
  // 来电自启状态
  "aS": false,
  // 童锁状态
  "cL": false
}
```

## 设备信息
- **请求方式**: `GET`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/getDeviceInfo`

**响应数据**:
```json
{
  "status": "ok",
  // 是否联网
  "oL": true,
  // WiFi 名称
  "wN": "Sumsg WiFi",
  // 设备 IP
  "wI": "10.10.0.139",
  // 设备 mac 地址
  "wM": "2C:3A:E8:35:F6:F2",
  // 设备序列号
  "SN": "000035F6F2",
  // 设备名称
  "hN": "HA-WBC-000035F6F2",
  "hP": false,
  "hV": "1.0.1",
  "hU": "2025-08-11",
  // 固件版本
  "fV": "1.0.1",
  // 固件更新时间
  "fU": "2025-08-11",
  // 固件更新进度
  "fG": 0,
  // 设备型号
  "mD": "HA-WBC-2",
  // 设备类型
  "mT": "WBC",
  // 设备内存大小
  "mF": 4194304
}
```

## 设置WiFi
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 如果已经配网需要认证, 出厂初始化状态不需要认证
- **请求地址**: `http://[设备IP]/api/setWiFi`
- **表单字段**: WiFi 名称: `ssid` , WiFi 密码: `password`

**响应数据**:
```json
{
  "status": "ok"
}
```

## 获取WiFi列表
- **请求方式**: `GET`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/getWifiList`

**响应数据**:
```json
{
"status": "ok",
  "list": [
    {
      "s": "25-10",
      "r": -79
    },
    {
      "s": "2508",
      "r": -78
    }
  ]
}
```

## 重启
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/restart`

**响应数据**:
```json
{
"status": "ok"
}
```

## 开关机
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;Content-Type: application/x-www-form-urlencoded;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/setPowerState`
- **请求参数**: 开机: `state=true` , 关机: `state=false`

**响应数据**:
```json
{
"status": "ok"
}
```

## 设置来的自启动
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;Content-Type: application/x-www-form-urlencoded;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/setAutoStartState`
- **请求参数**: 开启: `state=true` , 关闭: `state=false`

**响应数据**:
```json
{
"status": "ok"
}
```

## 设置童锁
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;Content-Type: application/x-www-form-urlencoded;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/setChildLockState`
- **请求参数**: 开启: `state=true` , 关闭: `state=false`

**响应数据**:
```json
{
"status": "ok"
}
```

## 强制关机
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/setForceShutdown`

**响应数据**:
```json
{
"status": "ok"
}
```

## 恢复出厂设置
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/factoryReset`

**响应数据**:
```json
{
"status": "ok"
}
```

## 检查固件更新
- **请求方式**: `GET`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/checkUpdate`

**响应数据**:
```json
{
"status": "ok"
}
```

## 获取固件更新进度
- **请求方式**: `GET`
- **是否认证**: 否
- **请求地址**: `http://[设备IP]/api/getUpdateProgress`

**响应数据**:
```json
{
  "status": "ok",
  "progress": "0"
}
```

## 执行固件更新
- **请求方式**: `POST`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/firmwareUpdate`

**响应数据**:
```json
{
"status": "ok"
}
```

## 验证 token
- **请求方式**: `GET`
- **请求头**: `Authorization: Bearer 1ffa46681a5484975eed1ca48ad130d5;`
- **是否认证**: 是
- **请求地址**: `http://[设备IP]/api/verifyToken`

**响应数据**:
```json
{
"status": "ok"
}
```
