"""示例：混淆后运行结果应与原版完全一致。"""
import math


def _secret_greeting(name):
    message = f"Hello, {name}!"
    return message


def calculate_total(prices, tax_rate=0.1):
    """算含税总价。"""
    subtotal = sum(prices)
    tax = subtotal * tax_rate
    total = subtotal + tax
    return round(total, 2)


def main():
    user_name = "Alice"
    print(_secret_greeting(user_name))
    prices = [10.0, 20.5, 5.25]
    print("total:", calculate_total(prices))
    print("sqrt:", math.sqrt(16))
    doubled = [x * 2 for x in prices if x > 6]
    print("doubled:", doubled)


if __name__ == "__main__":
    main()
