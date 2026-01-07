#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志过滤脚本：按进程号过滤IVI用户日志

功能：
1. 扫描指定目录下的所有IVI_user_log文件
2. 按序号排序（0, 1, 2, ...），无序号的文件放在最后（最新）
3. 过滤出指定进程号的日志行
4. 保存到新文件
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Optional


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


def filter_by_pid(lines: List[str], pid: int) -> List[str]:
    """
    过滤出包含指定进程号的日志行
    
    参数:
        lines: 日志行列表
        pid: 进程号
    
    返回:
        过滤后的日志行列表
    
    注意:
        只匹配PID和TID位置（日志格式的前两个数字位置），不匹配消息内容中的数字
        Android logcat格式: 日期 时间 PID TID 级别 标签: 消息
        例如: 01-07 04:30:34.433  3875  9139 D V4L2Device: ...
    """
    filtered = []
    pid_str = str(pid)
    
    # Android logcat格式: MM-DD HH:MM:SS.mmm  PID  TID 级别 标签: 消息
    # 精确匹配PID位置（时间戳后的第一个数字）或TID位置（PID后的第二个数字）
    # 不匹配消息内容中的数字
    # 匹配格式: 日期 时间 PID TID 或 日期 时间 PID（如果TID也是同一个数字）
    # 使用 ^ 开头确保从行首开始匹配，避免匹配消息内容中的数字
    pattern_pid = re.compile(
        r'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+' + pid_str + r'\s+\d+\s+[A-Z]'
    )  # 匹配PID位置
    pattern_tid = re.compile(
        r'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+' + pid_str + r'\s+[A-Z]'
    )  # 匹配TID位置
    
    for line in lines:
        # 检查是否在PID或TID位置匹配到进程号
        if pattern_pid.search(line) or pattern_tid.search(line):
            filtered.append(line.rstrip('\n\r'))
    
    return filtered


def main():
    parser = argparse.ArgumentParser(
        description='按进程号过滤IVI用户日志',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -d ivi -p 3875 -o filtered_3875.log
  %(prog)s --directory ./ivi --pid 3278 --output result.log
        """
    )
    
    parser.add_argument(
        '-d', '--directory',
        required=True,
        help='要扫描的目录路径'
    )
    
    parser.add_argument(
        '-p', '--pid',
        type=int,
        required=True,
        help='要过滤的进程号'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='输出文件路径（默认: filtered_pid_<进程号>.log）'
    )
    
    args = parser.parse_args()
    
    # 确定输出文件路径
    if args.output:
        output_path = args.output
    else:
        output_path = f"filtered_pid_{args.pid}.log"
    
    print(f"扫描目录: {args.directory}")
    print(f"目标进程号: {args.pid}")
    print(f"输出文件: {output_path}")
    print("-" * 60)
    
    # 获取并排序日志文件
    log_files = get_log_files(args.directory)
    
    if not log_files:
        print("错误: 未找到任何匹配的日志文件")
        return 1
    
    print(f"找到 {len(log_files)} 个日志文件")
    
    # 处理每个文件
    all_filtered_lines = []
    total_lines = 0
    filtered_count = 0
    
    for index, base_name, file_path in log_files:
        index_str = f"[{index}]" if index is not None else "[最新]"
        print(f"处理文件 {index_str}: {os.path.basename(file_path)}")
        
        # 读取文件
        lines = read_log_file(file_path)
        total_lines += len(lines)
        
        # 过滤
        filtered = filter_by_pid(lines, args.pid)
        filtered_count += len(filtered)
        
        if filtered:
            print(f"  找到 {len(filtered)} 条匹配的日志")
            all_filtered_lines.extend(filtered)
        else:
            print(f"  未找到匹配的日志")
    
    print("-" * 60)
    print(f"总计: 处理了 {total_lines} 行，找到 {filtered_count} 条匹配日志")
    
    # 写入输出文件
    if all_filtered_lines:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for line in all_filtered_lines:
                    f.write(line + '\n')
            print(f"成功保存到: {output_path}")
            return 0
        except Exception as e:
            print(f"错误: 无法写入输出文件: {e}")
            return 1
    else:
        print("警告: 未找到任何匹配的日志，不创建输出文件")
        return 0


if __name__ == '__main__':
    sys.exit(main())

