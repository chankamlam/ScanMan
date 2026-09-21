"""pytest 公共配置：把仓库根目录放进 ``sys.path``。

本项目不是可安装的包，所有脚本都靠"从仓库根目录启动"来 ``import src``。
测试沿用同一套约定即可 —— 不建包、不做 editable install，
换台机器 clone 下来就能直接 ``python -m pytest tests/``。
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
