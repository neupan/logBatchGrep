#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析语音请求延迟脚本

功能：
1. 从日志文件中提取每个请求（通过uuid标识）的关键时间点
2. 计算各种延迟指标
3. 输出到Excel表格
"""

import re
import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional, List, Tuple
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
# 设置中文字体
matplotlib.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False



def parse_timestamp(timestamp_str: str) -> Optional[float]:
    """
    解析Android logcat时间戳为Unix时间戳（秒）
    
    参数:
        timestamp_str: 时间戳字符串，格式: MM-DD HH:MM:SS.mmm
    
    返回:
        Unix时间戳（秒），如果解析失败返回None
    """
    try:
        # 假设年份是当前年份（或从日志上下文推断）
        # 格式: 01-15 14:08:19.690
        parts = timestamp_str.strip().split()
        if len(parts) != 2:
            return None
        
        date_part = parts[0]  # MM-DD
        time_part = parts[1]  # HH:MM:SS.mmm
        
        # 获取当前年份
        current_year = datetime.now().year
        
        # 组合完整时间字符串
        full_time_str = f"{current_year}-{date_part} {time_part}"
        
        # 解析为datetime对象
        dt = datetime.strptime(full_time_str, "%Y-%m-%d %H:%M:%S.%f")
        
        # 转换为Unix时间戳
        return dt.timestamp()
    except Exception as e:
        return None


def extract_uuid_from_start(line: str) -> Optional[Tuple[str, float]]:
    """
    从start消息中提取uuid和时间戳
    
    参数:
        line: 日志行
    
    返回:
        (uuid, timestamp) 元组，如果未匹配返回None
    """
    # 匹配: sendStartMsg start sending uuid is <uuid>, the start frame index is <number>
    pattern = r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}).*?sendStartMsg start sending uuid is\s+([a-f0-9-]+)'
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        uuid = match.group(2)
        timestamp = parse_timestamp(timestamp_str)
        if timestamp:
            return (uuid, timestamp)
    return None


def extract_uuid_from_stop(line: str) -> Optional[Tuple[str, float]]:
    """
    从stop消息中提取uuid和时间戳
    
    参数:
        line: 日志行
    
    返回:
        (uuid, timestamp) 元组，如果未匹配返回None
    """
    # 匹配: sendAudioMsg stop sending : <uuid>, the end frame index is <number>
    pattern = r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}).*?sendAudioMsg stop sending\s*:\s*([a-f0-9-]+)'
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        uuid = match.group(2)
        timestamp = parse_timestamp(timestamp_str)
        if timestamp:
            return (uuid, timestamp)
    return None


def extract_asr_message(line: str) -> Optional[Tuple[str, float, bool]]:
    """
    从ASR回复消息中提取uuid、时间戳和final标记
    
    参数:
        line: 日志行
    
    返回:
        (uuid, timestamp, is_final) 元组，如果未匹配返回None
    """
    # 匹配: recv message : {...}
    # 先提取时间戳
    timestamp_match = re.search(r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})', line)
    if not timestamp_match:
        return None
    
    timestamp_str = timestamp_match.group(1)
    
    # 找到 "recv message :" 的位置
    msg_pos = line.find('recv message :')
    if msg_pos == -1:
        return None
    
    # 从该位置开始提取JSON
    json_start = line.find('{', msg_pos)
    if json_start == -1:
        return None
    
    # 尝试解析JSON，需要找到匹配的结束括号
    brace_count = 0
    json_end = json_start
    in_string = False
    escape_next = False
    
    for i in range(json_start, len(line)):
        char = line[i]
        
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    break
    
    json_str = line[json_start:json_end]
    
    try:
        data = json.loads(json_str)
        # 检查是否是ASR消息
        # source在data下，不在data.content下
        source = data.get('data', {}).get('source')
        if source == 'asr':
            uuid = data.get('data', {}).get('content', {}).get('uuid')
            final = data.get('data', {}).get('content', {}).get('final', 0)
            timestamp = parse_timestamp(timestamp_str)
            if uuid and timestamp is not None:
                return (uuid, timestamp, final == 1)
    except (json.JSONDecodeError, KeyError, AttributeError):
        pass
    
    return None


def extract_nlu_message(line: str) -> Optional[Tuple[str, float, str]]:
    """
    从NLU回复消息中提取uuid、时间戳和norm_query
    
    参数:
        line: 日志行
    
    返回:
        (uuid, timestamp, norm_query) 元组，如果未匹配返回None
    """
    # 匹配: recv message : {...}
    # 先提取时间戳
    timestamp_match = re.search(r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})', line)
    if not timestamp_match:
        return None
    
    timestamp_str = timestamp_match.group(1)
    
    # 找到 "recv message :" 的位置
    msg_pos = line.find('recv message :')
    if msg_pos == -1:
        return None
    
    # 从该位置开始提取JSON
    json_start = line.find('{', msg_pos)
    if json_start == -1:
        return None
    
    # 尝试解析JSON，需要找到匹配的结束括号
    brace_count = 0
    json_end = json_start
    in_string = False
    escape_next = False
    
    for i in range(json_start, len(line)):
        char = line[i]
        
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    break
    
    json_str = line[json_start:json_end]
    
    try:
        data = json.loads(json_str)
        # 检查是否是NLU消息
        # source在data下，不在data.content下
        source = data.get('data', {}).get('source')
        if source == 'nlp':
            uuid = data.get('data', {}).get('content', {}).get('uuid')
            nlu_str = data.get('data', {}).get('content', {}).get('nlu', '{}')
            timestamp = parse_timestamp(timestamp_str)
            
            if uuid and timestamp is not None:
                # 解析nlu JSON字符串
                try:
                    nlu_data = json.loads(nlu_str)
                    norm_query = nlu_data.get('norm_query', '')
                    return (uuid, timestamp, norm_query)
                except json.JSONDecodeError:
                    # 如果没解析出来nlu，说明asr输入是空的，记录nlu时间，nlu内容为空
                    # print(f"错误: 无法解析 uuid: {uuid} 的nlu, line: {line}")
                    # 记录日志
                    # with open('nlu_error1.log', 'a') as f:
                    #     f.write(f"错误: 无法解析 uuid: {uuid} 的nlu, line: {line}\n")
                    return (uuid, timestamp, 'EMPTY')
    except (json.JSONDecodeError, KeyError, AttributeError):
        # JSON解析失败，可能是JSON不完整，尝试直接从日志字符串中提取
        # 检查是否是NLU消息（通过检查source字段）
        # print(f"JSON解析失败，可能是JSON不完整，尝试直接从日志字符串中提取, line: {line}")
        if '"nlu":' in line:
            timestamp = parse_timestamp(timestamp_str)
            # print(f"timestamp: {timestamp}")
            if timestamp is not None:
                # 尝试提取uuid
                uuid_match = re.search(r'"uuid"\s*:\s*"([a-f0-9-]+)"', line)
                uuid = uuid_match.group(1) if uuid_match else None
                # print(f"uuid: {uuid}")
                # 这适用于JSON被截断的情况
                # 注意：在转义的JSON字符串中，引号是转义的（\"norm_query\"）
                # 先尝试匹配转义引号格式
                direct_norm_query_match = re.search(r'\\"norm_query\\"\s*:\s*\\"([^"\\]+)\\"', line)
                if not direct_norm_query_match:
                    # 如果转义格式匹配不上，尝试普通引号格式（以防万一）
                    direct_norm_query_match = re.search(r'"norm_query"\s*:\s*"([^"]+)"', line)
                # 如果还是匹配不上，可能是值被截断了，尝试匹配到行尾
                if not direct_norm_query_match:
                    direct_norm_query_match = re.search(r'\\"norm_query\\"\s*:\s*\\"([^"\\]*)', line)
                # print(f"direct_norm_query_match: {direct_norm_query_match}")
                if direct_norm_query_match and uuid:
                    norm_query = direct_norm_query_match.group(1)
                    return (uuid, timestamp, norm_query)
    
    return None


def analyze_log_file(file_path: str) -> Dict[str, Dict]:
    """
    分析日志文件，提取所有请求的信息
    
    参数:
        file_path: 日志文件路径
    
    返回:
        字典，key为uuid，value为包含各时间点的字典
    """
    requests = defaultdict(lambda: {
        'uuid': None,
        'start_time': None,
        'stop_time': None,
        'first_asr_time': None,
        'last_asr_time': None,
        'nlu_time': None,
        'nlu_content': None,
    })
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # 提取start消息
                result = extract_uuid_from_start(line)
                if result:
                    uuid, timestamp = result
                    requests[uuid]['uuid'] = uuid
                    if requests[uuid]['start_time'] is None:
                        requests[uuid]['start_time'] = timestamp
                
                # 提取stop消息
                result = extract_uuid_from_stop(line)
                if result:
                    uuid, timestamp = result
                    requests[uuid]['uuid'] = uuid
                    if requests[uuid]['stop_time'] is None:
                        requests[uuid]['stop_time'] = timestamp
                
                # 提取ASR消息
                result = extract_asr_message(line)
                if result:
                    uuid, timestamp, is_final = result
                    requests[uuid]['uuid'] = uuid
                    if requests[uuid]['first_asr_time'] is None:
                        requests[uuid]['first_asr_time'] = timestamp
                    if is_final:
                        requests[uuid]['last_asr_time'] = timestamp
                
                # 提取NLU消息
                result = extract_nlu_message(line)
                if result:
                    uuid, timestamp, norm_query = result
                    requests[uuid]['uuid'] = uuid
                    if requests[uuid]['nlu_time'] is None:
                        requests[uuid]['nlu_time'] = timestamp
                        requests[uuid]['nlu_content'] = norm_query
    except Exception as e:
        print(f"错误: 无法读取文件 {file_path}: {e}")
        return {}
    
    # 过滤掉没有start_time的请求（不完整的请求）
    return {uuid: data for uuid, data in requests.items() if data['start_time'] is not None}


def plot_latency_distribution(df: pd.DataFrame, output_file: str):
    """
    绘制延迟分布图，为每个延迟指标生成独立的图片
    
    参数:
        df: DataFrame，包含延迟数据
        output_file: 输出图片文件路径（基础路径，会自动添加后缀）
    """
    # 要绘制的延迟列
    latency_cols = [
        'Start到Stop延迟(ms)',
        'Stop帧到最后一条ASR帧延迟(ms)',
        'Stop帧到NLU帧延迟(ms)'
    ]
    
    # 过滤出存在的列
    latency_cols = [col for col in latency_cols if col in df.columns]
    
    if not latency_cols:
        print("警告: 没有找到要绘制的延迟列")
        return
    
    # 颜色列表
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1']
    
    # 为每个延迟指标生成独立的图片
    for idx, col in enumerate(latency_cols):
        values = pd.to_numeric(df[col], errors='coerce').dropna()
        
        if len(values) == 0:
            print(f"警告: {col} 没有有效数据，跳过")
            continue
        
        # 创建图表，使用1行2列布局（直方图 + 统计表）
        fig = plt.figure(figsize=(16, 6))
        
        # 1. 直方图
        ax1 = plt.subplot(1, 2, 1)
        color = colors[idx % len(colors)]
        ax1.hist(values, bins=50, alpha=0.7, color=color, edgecolor='black', linewidth=0.5)
        ax1.set_xlabel('延迟 (ms)', fontsize=12)
        ax1.set_ylabel('频数', fontsize=12)
        ax1.set_title(f'{col} - 分布直方图', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        
        # 添加统计信息到图上
        mean_val = values.mean()
        median_val = values.median()
        ax1.axvline(mean_val, color='red', linestyle='--', linewidth=2, label=f'平均值: {mean_val:.2f} ms')
        ax1.axvline(median_val, color='blue', linestyle='--', linewidth=2, label=f'中位数: {median_val:.2f} ms')
        ax1.legend(fontsize=10)
        
        # 2. 统计摘要表
        ax2 = plt.subplot(1, 2, 2)
        ax2.axis('off')
        
        # 准备统计摘要数据
        summary_data = [[
            f"{values.mean():.2f}",
            f"{values.median():.2f}",
            f"{values.min():.2f}",
            f"{values.max():.2f}",
            f"{values.std():.2f}",
            f"{values.quantile(0.95):.2f}",
            f"{values.quantile(0.99):.2f}"
        ]]
        
        col_labels = ['平均值', '中位数', '最小值', '最大值', '标准差', 'P95', 'P99']
        table = ax2.table(
            cellText=summary_data,
            colLabels=col_labels,
            cellLoc='center',
            loc='center',
            bbox=[0, 0.3, 1, 0.4]
        )
        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1, 2.5)
        
        # 设置表头样式
        for i in range(len(col_labels)):
            table[(0, i)].set_facecolor('#4A90E2')
            table[(0, i)].set_text_props(weight='bold', color='white')
        
        # 设置数据行样式
        for j in range(len(col_labels)):
            table[(1, j)].set_facecolor('#F0F0F0')
        
        ax2.set_title(f'{col} - 统计摘要', fontsize=14, fontweight='bold', pad=20)
        
        # 生成输出文件名（在基础文件名后添加指标名称）
        base_name = output_file.replace('.png', '')
        # 简化列名作为文件名后缀，使用英文标识
        col_mapping = {
            'Start到Stop延迟(ms)': 'Start_to_Stop',
            'Stop帧到最后一条ASR帧延迟(ms)': 'Stop_to_LastASR',
            'Stop帧到NLU帧延迟(ms)': 'Stop_to_NLU'
        }
        col_suffix = col_mapping.get(col, col.replace('延迟(ms)', '').replace('到', '_').replace('帧', '').replace(' ', '_'))
        output_filename = f"{base_name}_{col_suffix}.png"
        
        plt.tight_layout()
        plt.savefig(output_filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  已生成: {output_filename}")


def plot_latency_timeseries(df: pd.DataFrame, output_file: str):
    """
    绘制延迟时间序列图，展示延迟随时间的变化
    
    参数:
        df: DataFrame，包含延迟数据和时间信息
        output_file: 输出图片文件路径（基础路径，会自动添加后缀）
    """
    # 检查是否有Start时间列
    if 'Start时间' not in df.columns:
        print("警告: 没有找到Start时间列，无法绘制时间序列图")
        return
    
    # 要绘制的延迟列
    latency_cols = [
        'Start到Stop延迟(ms)',
        'Stop帧到最后一条ASR帧延迟(ms)',
        'Stop帧到NLU帧延迟(ms)'
    ]
    
    # 过滤出存在的列
    latency_cols = [col for col in latency_cols if col in df.columns]
    
    if not latency_cols:
        print("警告: 没有找到要绘制的延迟列")
        return
    
    # 解析Start时间
    df['Start时间_parsed'] = pd.to_datetime(df['Start时间'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
    
    # 过滤掉无法解析时间的行
    df_valid = df[df['Start时间_parsed'].notna()].copy()
    
    if len(df_valid) == 0:
        print("警告: 没有有效的时间数据，无法绘制时间序列图")
        return
    
    # 按时间排序
    df_valid = df_valid.sort_values('Start时间_parsed')
    
    # 颜色列表
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1']
    
    # 为每个延迟指标生成独立的时间序列图
    for idx, col in enumerate(latency_cols):
        # 提取延迟值
        latency_values = pd.to_numeric(df_valid[col], errors='coerce')
        
        # 过滤掉无效值
        valid_mask = latency_values.notna()
        if valid_mask.sum() == 0:
            print(f"警告: {col} 没有有效数据，跳过")
            continue
        
        times = df_valid.loc[valid_mask, 'Start时间_parsed']
        values = latency_values[valid_mask]
        
        # 创建图表
        fig, ax = plt.subplots(figsize=(16, 8))
        
        color = colors[idx % len(colors)]
        
        # 绘制曲线
        ax.plot(times, values, color=color, linewidth=1.5, alpha=0.7, marker='o', markersize=3)
        
        # 添加平均值线
        mean_val = values.mean()
        ax.axhline(mean_val, color='red', linestyle='--', linewidth=2, alpha=0.7, label=f'平均值: {mean_val:.2f} ms')
        
        # 添加中位数线
        median_val = values.median()
        ax.axhline(median_val, color='blue', linestyle='--', linewidth=2, alpha=0.7, label=f'中位数: {median_val:.2f} ms')
        
        # 设置标签和标题
        ax.set_xlabel('时间', fontsize=12)
        ax.set_ylabel('延迟 (ms)', fontsize=12)
        ax.set_title(f'{col} - 时间序列图', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=10)
        
        # 格式化X轴时间显示
        fig.autofmt_xdate(rotation=45)
        
        # 添加统计信息文本
        stats_text = f'数据点数: {len(values)}\n'
        stats_text += f'平均值: {mean_val:.2f} ms\n'
        stats_text += f'中位数: {median_val:.2f} ms\n'
        stats_text += f'最小值: {values.min():.2f} ms\n'
        stats_text += f'最大值: {values.max():.2f} ms\n'
        stats_text += f'标准差: {values.std():.2f} ms'
        
        ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
                fontsize=9, verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        # 生成输出文件名
        base_name = output_file.replace('.png', '')
        col_mapping = {
            'Start到Stop延迟(ms)': 'Start_to_Stop',
            'Stop帧到最后一条ASR帧延迟(ms)': 'Stop_to_LastASR',
            'Stop帧到NLU帧延迟(ms)': 'Stop_to_NLU'
        }
        col_suffix = col_mapping.get(col, col.replace('延迟(ms)', '').replace('到', '_').replace('帧', '').replace(' ', '_'))
        output_filename = f"{base_name}_{col_suffix}.png"
        
        plt.tight_layout()
        plt.savefig(output_filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  已生成: {output_filename}")


def calculate_latencies(requests: Dict[str, Dict]) -> List[Dict]:
    """
    计算延迟并准备输出数据
    
    参数:
        requests: 请求字典
    
    返回:
        包含所有请求信息和延迟的列表
    """
    results = []
    
    for uuid, data in requests.items():
        result = {
            'UUID': uuid,
            'Start时间': datetime.fromtimestamp(data['start_time']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if data['start_time'] else '',
            'Stop时间': datetime.fromtimestamp(data['stop_time']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if data['stop_time'] else '',
            '第一条ASR时间': datetime.fromtimestamp(data['first_asr_time']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if data['first_asr_time'] else '',
            '最后一条ASR时间': datetime.fromtimestamp(data['last_asr_time']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if data['last_asr_time'] else '',
            'NLU时间': datetime.fromtimestamp(data['nlu_time']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if data['nlu_time'] else '',
            'NLU内容': data['nlu_content'] or '',
        }
        
        # 计算延迟（毫秒）
        if data['start_time']:
            # if data['first_asr_time']:
            #     result['Start到第一条ASR延迟(ms)'] = round((data['first_asr_time'] - data['start_time']) * 1000, 2)
            # else:
            #     result['Start到第一条ASR延迟(ms)'] = ''
            
            # if data['last_asr_time']:
            #     result['Start到最后一条ASR延迟(ms)'] = round((data['last_asr_time'] - data['start_time']) * 1000, 2)
            # else:
            #     result['Start到最后一条ASR延迟(ms)'] = ''
            
            # if data['nlu_time']:
            #     result['Start到NLU延迟(ms)'] = round((data['nlu_time'] - data['start_time']) * 1000, 2)
            # else:
            #     result['Start到NLU延迟(ms)'] = ''
            
            if data['stop_time']:
                result['Start到Stop延迟(ms)'] = round((data['stop_time'] - data['start_time']) * 1000, 2)
            else:
                result['Start到Stop延迟(ms)'] = ''
        else:
            pass
            
        if data['stop_time']:
            if data['last_asr_time']:
                result['Stop帧到最后一条ASR帧延迟(ms)'] = round((data['last_asr_time'] - data['stop_time']) * 1000, 2)
            else:
                result['Stop帧到最后一条ASR帧延迟(ms)'] = ''
            
            if data['nlu_time']:
                result['Stop帧到NLU帧延迟(ms)'] = round((data['nlu_time'] - data['stop_time']) * 1000, 2)
            else:
                result['Stop帧到NLU帧延迟(ms)'] = ''
        
        results.append(result)
    
    # 按Start时间排序
    results.sort(key=lambda x: x['Start时间'] if x['Start时间'] else '')
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='分析语音请求延迟',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -i filtered_pid_5668.log -o speech_latency.xlsx
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='输入日志文件路径'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='speech_latency.xlsx',
        help='输出Excel文件路径（默认: speech_latency.xlsx）'
    )
    
    args = parser.parse_args()
    
    print(f"分析日志文件: {args.input}")
    print("-" * 60)
    
    # 分析日志文件
    requests = analyze_log_file(args.input)
    
    if not requests:
        print("错误: 未找到任何请求")
        return 1
    
    print(f"找到 {len(requests)} 个请求")
    
    # 计算延迟
    results = calculate_latencies(requests)
    
    # 创建DataFrame
    df = pd.DataFrame(results)
    
    # 重新排列列的顺序
    column_order = [
        'UUID',
        'Start时间',
        'Stop时间',
        '第一条ASR时间',
        '最后一条ASR时间',
        'NLU时间',
        'NLU内容',
        'Start到Stop延迟(ms)',
        'Stop帧到最后一条ASR帧延迟(ms)',
        'Stop帧到NLU帧延迟(ms)'
    ]
    
    # 只保留存在的列
    column_order = [col for col in column_order if col in df.columns]
    df = df[column_order]
    
    # 保存到Excel
    try:
        df.to_excel(args.output, index=False, engine='openpyxl')
        print(f"成功保存到: {args.output}")
        print(f"共 {len(results)} 条记录")
        
        # 显示统计信息
        if results:
            print("\n统计信息:")
            latency_cols = [col for col in df.columns if '延迟(ms)' in col]
            for col in latency_cols:
                # 只处理数字类型的值
                valid_values = pd.to_numeric(df[col], errors='coerce').dropna()
                if len(valid_values) > 0:
                    print(f"  {col}:")
                    print(f"    平均值: {valid_values.mean():.2f} ms")
                    print(f"    最小值: {valid_values.min():.2f} ms")
                    print(f"    最大值: {valid_values.max():.2f} ms")
        
        # 绘制延迟分布图
        try:
            plot_file = args.output.replace('.xlsx', '_distribution')
            plot_latency_distribution(df, plot_file)
            print(f"\n延迟分布图已生成（每个指标一张图）")
        except Exception as e:
            print(f"警告: 无法生成分布图: {e}")
        
        # 绘制延迟时间序列图
        try:
            plot_file = args.output.replace('.xlsx', '_timeseries')
            plot_latency_timeseries(df, plot_file)
            print(f"\n延迟时间序列图已生成（每个指标一张图）")
        except Exception as e:
            print(f"警告: 无法生成时间序列图: {e}")
        
        return 0
    except Exception as e:
        print(f"错误: 无法保存Excel文件: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())

