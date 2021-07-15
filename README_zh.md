# **DeviceManager组件**

## 简介

DeviceManager组件是OpenHarmony为开发者提供的一套分布式设备账号无关的认证组网接口。

其组成及依赖如下所示：

![](figures/devicemanager_zh.png)

## 目录

```
foundation/distributedhardware/devicemanager
├── common
│   ├── log             #log相关头文件存放目录
│   └── utils           #公共能力头文件存放目录
├── interfaces
│   ├── inner_kits      #内部接口头文件存放目录
│   │   └── native_cpp  #内部native接口及实现存放目录
│    kits               #外接口头文件存放目录
│       └── js          #外部JS接口及实现存放目录
└── services
    └── devicemanagerservice    #devicemanagerservice服务实现核心代码
        ├── include
        │   ├── authdemo        #与设备认证相关头文件（非正式）
        │   └── softbus         #与软总线相关头文件
        └── src                 
            ├── authdemo        #设备认证功能示例代码（非正式）
            └── softbus         #通道建立及组网功能核心代码
```

## 约束

- 开发语言：JS
- 适用于Hi3516DV300单板等OpenHarmony设备


## 接口说明

当前版本设备管理服务不具备权限管理的能力。

以下模块的JS接口为非正式API，仅供分布式Demo应用使用，展示分布式能力，不排除对这些接口进行变更的可能性，后续版本将提供正式API。

参见 *ohos.distributedHardware.deviceManager.d.ts*

| 原型                                       | 描述       |
| -------                                   | ---------- |
| createDeviceManager(bundleName: string, callback: AsyncCallback<DeviceManager>): void                                   | 以异步方法获取DeviceManager实例  |
| release(): void                      | 释放DeviceManager实例  |
| getTrustedDeviceListSync(): Array<DeviceInfo>    | 获取信任设备列表  |
| authenticateDevice(deviceInfo: DeviceInfo): void   | 设备认证  |
| on(type: 'authResult', callback: Callback<{ deviceId: string, status: number, reason: number }>): void   | 订阅设备认证回调  |
| off(type: 'authResult', callback?: Callback<{ deviceId: string, status: number, reason: number }>): void   | 取消订阅设备认证回调  |


### 示例如下：
```
deviceManager.createDeviceManager(app.getInfo. appID, (err, data) => {
    if (err) {
        console.info(TAG + "createDeviceManager err:" + JSON.stringify(err));
        return;
    }
    console.info(TAG + "createDeviceManager success");
    dmClass = data;
}

var deviceInfo ={
    "deviceId": "XXXXXXXX",
    "deviceName": "",
    deviceType: 0
}；
dmClass.authenticateDevice(deviceInfo);
```

## 使用说明

当前版本是一个临时Demo认证方案，默认无法成功建立连接和PIN码认证，仅用于验证分布式能力，后续会提供正式的设备认证方案。

如果开发者感兴趣，可以通过修改代码来验证分布式能力。

**注：该方法存在一定安全风险，仅用于验证分布式能力。**
```
devicemanager\services\devicemanagerservice\src\authdemo\hichain_adapter.cpp

// PIN_CODE一般为随机6位数字字符串, 例如;
const std::string PIN_CODE = "123456";

// PORT为server端的监听端口号，随机端口范围一般为1024~65534, 例如
const int32_t PORT = 10001;
```

## 相关仓

**device_manager**
