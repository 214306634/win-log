# -*- coding: utf-8 -*-
import sys
import os
import ctypes
import platform

def is_admin():
    """检测当前进程是否拥有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新启动当前脚本（控制台窗口保持显示）"""
    if platform.system() != 'Windows':
        return
    script = os.path.abspath(sys.argv[0])
    # 使用 ShellExecuteW 以 runas 方式启动，nShowCmd = 1 表示正常显示窗口
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, script, None, 1
    )

if __name__ == '__main__':
    if not is_admin():
        # 非管理员，请求提权
        print("当前不是管理员权限，正在请求提升权限...")
        run_as_admin()
        sys.exit()  # 退出当前进程
    # 已获得管理员权限，继续执行主程序
    from gui import main
    main()
