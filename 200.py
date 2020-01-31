from itertools import product, chain
digits = "9876543210"
op = ["","+","-"]

f=lambda v:filter(eval,map(lambda e:"".join (chain(*zip(digits,e)))+v,product(op,repeat=9)))

print(*f("0==200"),sep="\n")
