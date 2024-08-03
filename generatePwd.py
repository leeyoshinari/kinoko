import time
import random

a = int(time.time() * 1000) + 3520567
b = random.randint(1, 3)
c = f"{b}{a}"
d = c[: b] + '5' + c[b:]
c = f"{d[5:10]}{d[10:15]}{d[0:5]}"
text = ''
for s in c:
    text += str(int(s)^1)
print(text)
