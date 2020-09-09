"""
argsparse是python的命令行解析的标准模块，内置于python，无需安装。
可以从命令行中向程序传入参数，并让程序运行。
https://zhuanlan.zhihu.com/p/56922793
"""
import argparse

parser = argparse.ArgumentParser(description='命令行中传入一个数字')
# type是要传入的参数的数据类型  help是该参数的提示信息
# nargs表示传入的参数的个数“+”表示至少一个参数
# default可以表示默认值
parser.add_argument('integers', type = int, nargs = '+', help='传入的数字')
args = parser.parse_args()
# 获得传入的参数
# print(args)
# Namespace(integers='5')是一种类似于python字典的数据类型，使用以下命令提取该参数值。
print(sum(args.integers))

