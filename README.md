# pyobf — 纯 CLI 的 Python 代码混淆器

**版本：v0.1alpha.4 · 纯标准库，零第三方依赖 · Python 3.9+**

目标不是“不可逆加密”，而是：**混淆后代码照常运行，变量名、字符串、注释不再一眼看穿，且改名是 AST 级别的，不会把字符串里的单词或注释误改。**

## v0.1alpha.4 相对 alpha.3 的增强：虚拟机保护（VMP）

- **新增 VMP（level 3 默认开启，`--vmp` / `--no-vmp`）**：符合条件的顶层函数被编译成自定义栈式 VM 字节码，原来的 Python 逻辑在产物里完全看不见，只剩一个内嵌解释器和一段 base64 载荷（载荷本身还会被字符串加密再拆分）。`hello.py` 的 `calculate_total`、`vmpy.py` 的 6 个函数已进 VM，输出与原版完全一致。
- **VM 支持的子集**：赋值/复合赋值、表达式、`return`、`if`/`while`/`for`/`break`/`continue`，算术/比较/逻辑运算（`and`/`or` 短路）、`if` 表达式、位置参数调用、索引/切片、列表/元组、属性读写。不支持的（`try`/`with`/`match`/推导式/嵌套函数/`yield`/装饰器以外的动态特性等）**自动回退**，原样走普通混淆，不会半编译。
- **跨文件私有调用也通**：VM 里的全局名按顶层映射翻译（`_BASE`、`from helper import _double` 这类私有名字在 VM 里按改名后的名字查），解释器在运行时拿 `globals()` 查，内置函数走 `__builtins__`。
- **解释器本身也是混淆目标**：它用短变量名写，插入后不参与改名，但它的常量（操作码、载荷）全在 base64 里。

## v0.1alpha.3 相对 alpha.2 的增强

- **私有属性也改名（level ≥ 2）**：`self._count`、`cls._x`、私有方法、类体 `_limit = ...` 按类统一改名。公开属性（`self.count`）不动。代价：类外面的 `obj._x` 不会跟着改，访问私有属性的外部代码会失效——私有属性本来就不该从外面碰。
- **bytes 也加密，长字符串拆分**：`b"..."` 用独立的 bytes helper 解码；≥20 字符的字符串拆成两段，各自独立加盐，用 `+` 拼回，单个载荷里不再有完整原文。
- **整数不再能被常量折叠还原**：alpha.2 的 `a + b` 拆分会被 CPython 编译期折叠回原值，`.pyc` 里照样有原整数。现在改成 `len("xxxx") * k + r` 这种运行时表达式，编译后的常量里找不到原整数。`match` 字面模式、注解、小于 10 的整数仍不碰；局部变量遮住 `len` 时回退到加法拆分。
- **顶层函数乱序（level 3）**：只打乱定义期不依赖其他顶层名字的函数，顶层语句引用了顶层函数的文件整文件跳过乱序。`hello.py` / `demo.py` / `vmpy.py` 样本在 level 3 下输出与原版完全一致（vmpy 样本在本地 `vmpy-sample` 分支，不随 main 推送）。

## v0.1alpha.2 相对 alpha 的增强

- **字符串逐串加盐**：alpha 的全局 XOR 密钥 + 固定 `_pyobf_s` helper，一处泄露等于全部泄露。现在每串有自己的 4 字节盐，密钥是 `SHA256(master + salt)`，master 只以 `bytes([...])` 形式嵌在 helper 里；helper 名每个文件都不同，没有固定标记可 grep。
- **整数混淆（level ≥ 2）**：`16` → `692 + -676` 这类确定性加法拆分，`match` 的字面模式、注解、小整数（<10）不碰。
- **私有模块变量也改名（level ≥ 2）**：`_FACTOR = 10` 这类模块级私有变量进全项目统一映射，跨文件 `from cfg import _FACTOR` / `cfg._FACTOR` 一起改。
- **标识符不再是固定模式**：alpha 是 `_o` + 8 位 hex，现在长度在 6–12 位之间变化。
- **死代码不再是 `if False:`（level 3）**：改成不透明谓词（如 `if 79 * 37 % 7 == 5:`，按构造恒为假）加一个永不调用的函数。

> 诚实声明：混淆 ≠ 加密。懂行的人用 `ast` / 反编译仍可还原逻辑。不要把密钥、密码放进要混淆的代码里指望它保密。

## 快速开始

```bash
# 单文件，默认 level 1（在项目根目录下运行）
python -m pyobf -i examples/hello.py -o /tmp/hello_obf.py --seed 42

# 下面两种写法也一样能用：
python pyobf/cli.py -i examples/hello.py -o /tmp/hello_obf.py --seed 42
cd pyobf && python cli.py -i ../examples/hello.py -o /tmp/hello_obf.py --seed 42

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
| 2 | level 1 + 私有顶层 `def`/`class`/变量和私有属性重命名 + 逐串加盐字符串与 bytes 加密（长串拆分）+ 不可折叠整数混淆 | — |
| 3 | level 2 + 不透明死代码（恒假谓词 + 永不调用的函数）+ 顶层函数乱序 + 虚拟机保护（VMP） | — |

可单独开关：`--no-strings`、`--no-ints`、`--no-rename-top`、`--no-attrs`、`--no-shuffle`、`--no-vmp`、`--no-junk`、`--keep-docstrings`。

## 它保证不改什么（安全规则）

- **不改公开属性名**：`obj.attr`、`self.count`、`obj.method()` 原样保留；只有私有属性（`self._x`、私有方法、类体私有变量）在 level ≥ 2 时按类改名。
- **不改 import**：`import os`、`from x import y` 的绑定名保留；跨文件私有函数/变量（`from helper import _helper`、`helper._helper`、`cfg._FACTOR`）在 level 2 用全项目统一映射一起改，`__all__` 也会同步更新。
- **不改内置函数和 dunder**：`len`、`print`、`__name__`、`__main__` 不动。
- **不改函数参数（默认）**：关键字调用 `f(name="Bob")` 不会断。想改参数用实验性 `--rename-args`，它只改写同文件内直接调用的关键字参数。
- **闭包 / global / nonlocal / 海象 / match / 推导式首个迭代器**都按 Python 作用域语义处理，见 `tests/test_transform.py`。
- **字符串加密只针对 ≥4 字符的普通字符串常量**，f-string 字面部分、注解、docstring 不加密；解码后值完全相同。bytes 同理（独立 helper）；≥20 字符的长串拆成两段分别加密。

## 选项

```
-i / --input       输入：单个 .py 或目录（必填）
-o / --output      输出：文件或目录。默认 输入名 + _obf
--seed             种子。不给则随机生成并打印，用同一 seed 可复现同一输出
--level 1|2|3      强度，默认 1
--ints / --no-ints 混淆整数常量（level>=2 默认开启）
--attrs / --no-attrs 重命名私有属性（level>=2 默认开启）
--shuffle / --no-shuffle 打乱顶层函数顺序（level 3 默认开启）
--vmp / --no-vmp 虚拟机保护（level 3 默认开启）
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
  __init__.py      版本号 0.1.0-alpha.4
  __main__.py      python -m pyobf 入口
  cli.py           argparse、退出码、输出目录保护
  obfuscator.py    发现文件、两遍式顶层映射、插入 helper/死代码/VM 解释器、顶层乱序、写盘
  transform.py     AST 重命名器（作用域、推导式、import、关键字调用、私有属性、整数混淆）
  vm.py            VMP：把函数编译成自定义栈式 VM 字节码 + 内嵌解释器
  naming.py        确定性命名：sha256(seed + 作用域 + 原名)，长度 6–12 位
  strings.py       逐串加盐 XOR + base64 字符串/bytes 加解密与运行时 helper
tests/             unittest，无第三方依赖：python -m unittest discover -s tests -v
examples/          hello.py、demo.py（混淆前后输出应一致）
```

## 测试

```bash
python -m unittest discover -s tests -v
```

覆盖：字符串/bytes 往返与逐串盐、命名确定性、混淆后运行输出一致、内置/公开属性/import 不动、私有属性改名、闭包/global/match/海象、跨文件私有 import（含私有模块变量）、整数混淆与 match 模式保护及编译后常量检查、长串拆分、顶层乱序、VMP（VM 单元测试 + 混淆后输出一致 + 跨文件私有调用 + 默认参数）、无固定 helper 名、不透明死代码、关键字参数、语法错误、dry-run、CLI 退出码。共 50 个测试。

## 已知限制（v0.1alpha.4，下一版再修）

1. 用 `ast.unparse` 重生成代码：**注释、空行、原格式会丢**，只保语义；`# type:` 注释、部分极端语法可能丢失。
2. 不改文件名、不改模块名；`getattr(obj, "_helper")` 这类**字符串形式的动态属性名**不会跟着顶层改名走。
3. `eval` / `exec` / `globals()` 里的字符串变量名不会被改写，混淆后这些动态引用会失效——不要对含动态取名的代码用 level 2 的顶层改名。
4. 字符串 `is` 身份比较（如 `x is "foo"`）在加密后可能变 False，请用 `==`。
5. `--rename-args` 跨文件关键字调用、通过变量间接调用的函数，关键字参数可能失效，默认关闭。
6. 只支持 UTF-8 的 `.py`；语法错误的文件会直接报错退出，不跳过。
7. 类外面直接碰私有属性（`obj._x`、`getattr(obj, "_x")`）不会跟着私有属性改名走，level ≥ 2 下这类代码会失效；模块级变量遮住 `len` 时整数混淆会回退到加法拆分。
8. VMP 只做顶层函数，类方法、嵌套函数不在内；VM 里的函数调用仍走正常 Python 调用（解释器本身是 Python 写的，速度比原生慢，热路径别用 VMP）；VM 载荷里的字符串/整数以 base64 + 加密形式存放，不是加密算法，懂解释器的人仍可解码。

## 下一步（v0.2 候选）

- VMP 扩展到类方法、控制流扁平化（状态机分发，限简单函数）
- 保留原格式的改名（tokenize 方式，不走 unparse）
- `--keep-public-api`：按 `__all__` 自动保留公开接口
- 字节码 / `.pyc` 输出模式
