import os
import sys

print("脚本开始")

def find_executables(path):
    """扫描目录以查找可执行文件（.exe, .com）。"""
    print(f"开始扫描: {path}")
    executables = []
    try:
        for root, dirs, files in os.walk(path):
            print(f"正在扫描: {root}")
            for file in files:
                if file.lower().endswith((".exe", ".com")):
                    print(f"  找到: {file}")
                    executables.append(file)
    except Exception as e:
        print(f"扫描时发生错误: {e}")
    print(f"扫描完成，找到 {len(executables)} 个可执行文件")
    return executables

def generate_rules(executables):
    """根据可执行文件列表生成规则字符串。"""
    if not executables:
        return ""
    
    rules = []
    for exe in executables:
        # 默认情况下，为每个可执行文件启用TCP和UDP加速
        rules.append(f"{exe};1;1") 

    return "/".join(rules)

if __name__ == "__main__":
    print("主函数入口")
    if len(sys.argv) != 2:
        print("使用方法: python generate_rules.py <要扫描的目录>")
        sys.exit(1)

    scan_path = sys.argv[1]
    print(f"获取到的路径参数: '{scan_path}'")

    # 在 Windows 上，当一个带引号的路径以反斜杠结尾时，命令行参数解析可能会出错，
    # 导致路径字符串末尾包含一个多余的引号。
    # 此代码块会检查并移除这个多余的引号。
    if sys.platform == 'win32' and scan_path.endswith('"'):
        scan_path = scan_path[:-1]

    if not os.path.isdir(scan_path):
        print(f"错误: 目录 '{scan_path}' 不是一个有效的目录。")
        sys.exit(1)

    print(f"准备开始扫描...")
    executables = find_executables(scan_path)

    if not executables:
        print("在指定目录中未找到可执行文件 (.exe, .com)。")
    else:
        rules_string = generate_rules(executables)
        print("\n找到的可执行文件:")
        for exe in executables:
            print(f"- {exe}")
        
        print("\n生成的规则列表字符串:")
        print(rules_string)

print("脚本结束")