#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'carpedm20'

import os
import sys
from f import *
from kakao2 import *
from PIL import Image
from emo import emo
from timeout import timeout
import xml.dom.minidom as minidom
from xgoogle.search import GoogleSearch, SearchError
import mechanize

chatId = 0L
s = start()
suc = write(s, chatId, "(하트)")
