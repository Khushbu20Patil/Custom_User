from datetime import date


def cal(born):
    print(born)
    today = date.today()
    return today.year - born.year


