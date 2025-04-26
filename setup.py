import sys
import os
from cx_Freeze import setup, Executable

# 设置各种目录路径
build_exe_options = {
    "packages": ["dpkt", "customtkinter", "tkinter", "queue", "collections", "os", "socket", "traceback"],
    "excludes": ["tkinter.test"],
    "include_files": ["ip.ico"],
    "optimize": 2,
}

# 设置可执行文件
base = None
if sys.platform == "win32":
    base = "Win32GUI"  # 不显示控制台窗口

setup(
    name="IP流量分析器",
    version="1.0",
    description="IP流量分析工具",
    options={"build_exe": build_exe_options},
    executables=[
        Executable(
            "main.py",
            base=base,
            icon="ip.ico",
            target_name="IP流量分析器.exe"
        )
    ]
)