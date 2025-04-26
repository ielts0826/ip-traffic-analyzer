# IP流量分析器

一个用于分析IP网络流量的桌面应用工具。

## 功能特点

- IP流量实时监控
- 流量数据分析
- 用户友好的图形界面
- 支持数据导出

## 安装说明

1. 下载最新的安装包 `IP流量分析器_Setup.exe`
2. 运行安装程序
3. 按照安装向导的提示完成安装

## 开发环境

- Python 3.12
- Windows 10/11

## 构建说明

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 构建可执行文件：
```bash
python setup.py build
```

3. 创建安装程序：
使用Inno Setup编译 installer.iss 文件

## 许可证

MIT License