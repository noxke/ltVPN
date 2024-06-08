#!/bin/bash

# 关闭时间同步
timedatectl set-ntp no
# 获取当前时间戳
current_timestamp=$(date +%s)

# 默认增加的天数为0
days_to_add=0

if [[ $# -eq 1 ]]; then
  # 获取传递的参数
  modifier="$1"

  # 提取符号和天数
  sign="${modifier:0:1}"
  days="${modifier:1}"

  # 验证传递的参数格式
  if [[ $sign != "+" && $sign != "-" ]] || ! [[ $days =~ ^[0-9]+$ ]]; then
    echo "参数格式无效。请使用+xx或-xx，其中xx为整数天数。"
    exit 1
  fi

  # 根据符号设置增加或减少天数
  if [[ $sign == "+" ]]; then
    days_to_add=$days
  elif [[ $sign == "-" ]]; then
    days_to_add=$((-$days))
  fi
else
  echo "请提供+xx或-xx的参数，其中xx为整数天数。"
  exit 1
fi

# 计算修改后的时间戳
modified_timestamp=$((current_timestamp + days_to_add * 86400))

# 格式化为日期时间
modified_date=$(date -d @$modified_timestamp)

echo "当前日期时间: $(date)"
date -s "$modified_date"
echo "修改后的日期时间: $(date)"