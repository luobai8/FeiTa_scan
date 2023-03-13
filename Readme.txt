飞塔扫描工具
飞塔扫描工具可以自动化搜集一些网站信息，帮助渗透测试人员节省时间，功能待完善

命令功能如下：

-u ：目标网站地址，注意不要加上http，否则会失败

-cdn ：检查目标网站是否存在cdn

-cms ：检查目标网站的一些网站指纹，显示数量或多或少，应该是有一些网站做了过滤吧

-domain ：探测网站子域名

-whois ：查询网站whois信息

-port ：探测网站开放的端口

-path ：扫描网站的某些文件，备份文件

-all ：配合 -u 命令将上面的流程全部走一遍，不包括 -path 因为这个耗时太长
注意：

第一个参数必须为 -u

 尽量不要使用 -path参数来查询网站路径，这个功能待完善，速度较慢
 如果您坚持使用，那将很可能会花费您十几甚至几十分钟
 
 ---------------------------------------------执行结果会存在result目录下的对应txt文档中----------------------------------------
测试环境为python3.7.8, 项目中用到的的依赖包如:: import json

import socket

import os

import sys

import time

import zlib

import whois

import re

import requests

from bs4 import BeautifulSoup

from lxml import etree
在使用过程中有任何问题可添加作者qq：2083231780

欢迎各位大佬做内容补充
	 
