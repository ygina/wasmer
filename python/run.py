import os
print('create/write')
with open('python/tmp0.txt', 'w+') as f:
    f.write('apple')
with open('python/tmp1.txt', 'w+') as f:
    f.write('banana')
print('rename')
os.rename('python/tmp1.txt', 'python/tmp2.txt')
print('delete')
os.remove('python/tmp0.txt')

