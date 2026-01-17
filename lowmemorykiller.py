#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提取 lowmemorykiller 日志中的应用名

功能：
1. 扫描指定目录下的所有IVI_user_log文件（复用filter_logs_by_pid.py的规则）
2. 按序号排序（0, 1, 2, ...），无序号的文件放在最后（最新）
3. 查找所有包含 lowmemorykiller 的日志行
4. 提取应用名（单引号中的内容）
5. 去重并输出所有应用名
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Optional, Set


def parse_log_filename(filename: str) -> Tuple[Optional[int], str]:
    """
    解析日志文件名，提取序号和基础名称
    
    参数:
        filename: 文件名，例如 "IVI_user_log_2_20260106-201833321.log" 或 "IVI_user_log_20260107-043034434.log"
    
    返回:
        (序号, 基础名称) 元组，如果没有序号则序号为None
        基础名称不包含扩展名（.log）
    """
    # 只处理.log文件，去掉扩展名
    if not filename.endswith('.log'):
        return (None, None)
    
    base_filename = filename[:-4]  # 去掉 .log
    
    # 匹配格式: IVI_user_log_<序号>_<时间戳> 或 IVI_user_log_<时间戳>
    pattern_with_index = r'IVI_user_log_(\d+)_(.+)$'
    pattern_without_index = r'IVI_user_log_(.+)$'
    
    match = re.match(pattern_with_index, base_filename)
    if match:
        index = int(match.group(1))
        base_name = match.group(2)
        return (index, base_name)
    
    match = re.match(pattern_without_index, base_filename)
    if match:
        base_name = match.group(1)
        return (None, base_name)
    
    return (None, None)


def get_log_files(directory: str) -> List[Tuple[Optional[int], str, str]]:
    """
    扫描目录，获取所有IVI_user_log文件并排序
    
    参数:
        directory: 目录路径
    
    返回:
        排序后的文件列表，每个元素为 (序号, 基础名称, 完整路径)
        序号为None的文件（无序号）会放在最后
        只处理.log文件，忽略.zst压缩文件
    """
    log_files = []
    dir_path = Path(directory)
    
    if not dir_path.exists():
        print(f"错误: 目录不存在: {directory}")
        return []
    
    # 扫描所有匹配的.log文件（忽略.zst文件）
    for file_path in dir_path.iterdir():
        if not file_path.is_file():
            continue
        
        filename = file_path.name
        if not filename.startswith('IVI_user_log_'):
            continue
        
        # 只处理.log文件，忽略.zst文件
        if not filename.endswith('.log'):
            continue
        
        index, base_name = parse_log_filename(filename)
        
        if base_name is not None:
            log_files.append((index, base_name, str(file_path)))
    
    # 排序：有序号的按序号排序，无序号（None）的放在最后
    def sort_key(item):
        index, base_name, _ = item
        if index is None:
            # 无序号的文件放在最后，使用一个很大的数字
            return (float('inf'), base_name)
        return (index, base_name)
    
    log_files.sort(key=sort_key)
    return log_files


def read_log_file(file_path: str) -> List[str]:
    """
    读取日志文件
    
    参数:
        file_path: 文件路径
    
    返回:
        日志行列表
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        print(f"警告: 无法读取文件 {file_path}: {e}")
        return []


def extract_app_names_from_lowmemorykiller(lines: List[str]) -> Set[str]:
    """
    从 lowmemorykiller 日志中提取应用名
    
    参数:
        lines: 日志行列表
    
    返回:
        应用名集合（去重）
    
    日志格式示例:
        01-06 19:21:37.691  3275  3275 I lowmemorykiller: Kill 'com.gua.car.casting' (22320), uid 1001000, ...
    """
    app_names = set()
    
    # 匹配 lowmemorykiller 日志行，提取单引号中的应用名
    # 格式: ... lowmemorykiller: Kill '应用名' (PID), ...
    pattern = re.compile(
        r"lowmemorykiller:\s+Kill\s+'([^']+)'\s+\(",
        re.IGNORECASE
    )
    
    for line in lines:
        match = pattern.search(line)
        if match:
            app_name = match.group(1)
            app_names.add(app_name)
    
    return app_names


def main():
    parser = argparse.ArgumentParser(
        description='从 lowmemorykiller 日志中提取应用名',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -d ivi
  %(prog)s --directory ./ivi --output app_names.txt
        """
    )
    
    parser.add_argument(
        '-d', '--directory',
        required=True,
        help='要扫描的目录路径'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='输出文件路径（默认: 输出到标准输出）'
    )
    
    args = parser.parse_args()
    
    print(f"扫描目录: {args.directory}")
    print("-" * 60)
    
    # 获取并排序日志文件
    log_files = get_log_files(args.directory)
    
    if not log_files:
        print("错误: 未找到任何匹配的日志文件")
        return 1
    
    print(f"找到 {len(log_files)} 个日志文件")
    
    # 处理每个文件，收集所有应用名
    all_app_names = set()
    total_lines = 0
    matched_lines_count = 0
    
    for index, base_name, file_path in log_files:
        index_str = f"[{index}]" if index is not None else "[最新]"
        print(f"处理文件 {index_str}: {os.path.basename(file_path)}")
        
        # 读取文件
        lines = read_log_file(file_path)
        total_lines += len(lines)
        
        # 提取应用名
        app_names = extract_app_names_from_lowmemorykiller(lines)
        
        if app_names:
            print(f"  找到 {len(app_names)} 个应用名: {', '.join(sorted(app_names))}")
            all_app_names.update(app_names)
            # 统计匹配的行数（粗略估计）
            matched_lines = [line for line in lines if 'lowmemorykiller' in line.lower()]
            matched_lines_count += len(matched_lines)
        else:
            print(f"  未找到 lowmemorykiller 日志")
    
    print("-" * 60)
    print(f"总计: 处理了 {total_lines} 行，找到 {matched_lines_count} 条 lowmemorykiller 日志")
    print(f"提取到 {len(all_app_names)} 个唯一的应用名")
    
    # 输出结果
    if all_app_names:
        sorted_app_names = sorted(all_app_names)
        
        if args.output:
            # 输出到文件
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for app_name in sorted_app_names:
                        f.write(app_name + '\n')
                print(f"\n成功保存到: {args.output}")
                print(f"应用名列表（共 {len(sorted_app_names)} 个）:")
                for app_name in sorted_app_names:
                    print(f"  - {app_name}")
                return 0
            except Exception as e:
                print(f"错误: 无法写入输出文件: {e}")
                return 1
        else:
            # 输出到标准输出
            print(f"\n应用名列表（共 {len(sorted_app_names)} 个）:")
            for app_name in sorted_app_names:
                print(f"  - {app_name}")
            return 0
    else:
        print("\n警告: 未找到任何 lowmemorykiller 日志，未提取到应用名")
        return 0


if __name__ == '__main__':
    sys.exit(main())

