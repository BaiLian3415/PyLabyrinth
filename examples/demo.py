"""示例 2：覆盖闭包、异常、with、类方法、关键字调用。"""
import json


class Counter:
    def __init__(self):
        self.count = 0

    def increment(self, step=1):
        self.count += step
        return self.count


def make_multiplier(factor):
    def multiply(value):
        return value * factor

    return multiply


def _load_config(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        print("bad config:", err)
        return {}
    return data


def main():
    counter = Counter()
    print(counter.increment(step=2))
    double = make_multiplier(2)
    print(double(21))
    cfg = _load_config('{"key": "value", "n": 3}')
    print(cfg["key"], cfg["n"])
    total = 0
    for i, v in enumerate([1, 2, 3]):
        total += v
    print("total:", total)
    import io
    from contextlib import closing

    with closing(io.StringIO("hello")) as buf:
        print("buf:", buf.read())


if __name__ == "__main__":
    main()
