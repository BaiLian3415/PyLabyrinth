# pyobf — 纯 CLI 的 Python 代码混淆器

**版本：v0.1alpha · 纯标准库，零第三方依赖 · Python 3.9+**

从 0 写的第一个可用版本。目标不是“不可逆加密”，而是：**混淆后代码照常运行，变量名、字符串、注释不再一眼看穿，且改名是 AST 级别的，不会把字符串里的单词或注释误改。**

> 诚实声明：混淆 ≠ 加密。懂行的人用 `ast` / 反编译仍可还原逻辑。不要把密钥、密码放进要混淆的代码里指望它保密。

## 快速开始

```bash
# 单文件，默认 level 1
python -m pyobf -i examples/hello.py -o /tmp/hello_obf.py --seed 42

# 整个目录，level 2
python -m pyobf -i myproject -o myproject_obf --seed 42 --level 2 --map map.json

# 先试运行，不写文件
python -m pyobf -i myproject -o myproject_obf --dry-run

# 验证混淆后还能跑
python /tmp/hello_obf.py
```

## 强度等级

| level | 做什么 | 默认 |
|---|---|---|
| 1 | 局部变量 / 循环 / with / except / 推导式变量重命名；删注释和 docstring | 默认 |
| 2 | level 1 + 私有顶层 `def`/`class`（`_xxx`）重命名 + 字符串加密（XOR+base64，运行时解码） | — |
| 3 | level 2 + 插入死代码（`if False:`，永不执行） | — |

可单独开关：`--no-strings`、`--no-rename-top`、`--no-junk`、`--keep-docstrings`。

## 它保证不改什么（安全规则）

- **不改属性名**：`obj.attr`、`self.count`、`obj.method()` 原样保留。
- **不改 import**：`import os`、`from x import y` 的绑定名保留；跨文件私有函数（`from helper import _helper`、`helper._helper`）在 level 2 用全项目统一映射一起改，`__all__` 也会同步更新。
- **不改内置函数和 dunder**：`len`、`print`、`__name__`、`__main__` 不动。
- **不改函数参数（默认）**：关键字调用 `f(name="Bob")` 不会断。想改参数用实验性 `--rename-args`，它只改写同文件内直接调用的关键字参数。
- **闭包 / global / nonlocal / 海象 / match / 推导式首个迭代器**都按 Python 作用域语义处理，见 `tests/test_transform.py`。
- **字符串加密只针对 ≥4 字符的普通字符串常量**，f-string 字面部分、注解、docstring 不加密；解码后值完全相同。

## 选项

```
-i / --input       输入：单个 .py 或目录（必填）
-o / --output      输出：文件或目录。默认 输入名 + _obf
--seed             种子。不给则随机生成并打印，用同一 seed 可复现同一输出
--level 1|2|3      强度，默认 1
--rename-args      实验性：重命名函数参数
--keep-name NAME   永不重命名的标识符，可重复
--exclude GLOB     排除文件，可重复，如 'test_*.py'
--map FILE         写 原名->混淆名 的 JSON 映射（调试用，发布时不要分发）
--dry-run          只检查统计，不写文件
--force            输出目录已存在且有 .py 时直接覆盖
-q / -v            安静 / 详细
```

## 项目结构

```
pyobf/
  __init__.py      版本号 0.1.0-alpha
  __main__.py      python -m pyobf 入口
  cli.py           argparse、退出码、输出目录保护
  obfuscator.py    发现文件、两遍式顶层映射、插入 helper/死代码、写盘
  transform.py     AST 重命名器（作用域、推导式、import、关键字调用）
  naming.py        确定性命名：sha256(seed + 作用域 + 原名)
  strings.py       XOR + base64 字符串加解密与运行时 helper
tests/             unittest，无第三方依赖：python -m unittest discover -s tests -v
examples/          hello.py、demo.py（混淆前后输出应一致）
```

## 测试

```bash
python -m unittest discover -s tests -v
```

覆盖：字符串往返、命名确定性、混淆后运行输出一致、内置/属性/import 不动、闭包/global/match/海象、跨文件私有 import、关键字参数、语法错误、dry-run、CLI 退出码。

## 已知限制（v0.1alpha，下一版再修）

1. 用 `ast.unparse` 重生成代码：**注释、空行、原格式会丢**，只保语义；`# type:` 注释、部分极端语法可能丢失。
2. 不改文件名、不改模块名；`getattr(obj, "_helper")` 这类**字符串形式的动态属性名**不会跟着顶层改名走。
3. `eval` / `exec` / `globals()` 里的字符串变量名不会被改写，混淆后这些动态引用会失效——不要对含动态取名的代码用 level 2 的顶层改名。
4. 字符串 `is` 身份比较（如 `x is "foo"`）在加密后可能变 False，请用 `==`。
5. `--rename-args` 跨文件关键字调用、通过变量间接调用的函数，关键字参数可能失效，默认关闭。
6. 只支持 UTF-8 的 `.py`；语法错误的文件会直接报错退出，不跳过。

## 下一步（v0.2 候选）

- 控制流扁平化 / 不透明谓词、常量折叠后加密
- 保留原格式的改名（tokenize 方式，不走 unparse）
- `--keep-public-api`：按 `__all__` 自动保留公开接口
- 字节码 / `.pyc` 输出模式
