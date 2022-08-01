from random import gauss, randint
from copy import deepcopy

class Poly:
    def __init__(self, n, q):
        self.n = n
        self.q = q
        self.cofficient = [0]*n

    def randomize(self, B=2, type=0, sigma=0, mu=0):
        if type == 0:
            self.cofficient = [randint(-B//2, B//2) for i in range(self.n)]
        elif type == 1:
            self.cofficient = [int(gauss(mu, sigma)) for i in range(self.n)]
        else:
            self.cofficient = [randint(0, 1) for i in range(self.n)]

    def __add__(self, other):
        if type(other) is Poly:
            if self.q != other.q:
                raise Exception("Polynomial Addiditon: Inputs must have the same modulus")
            else:
                c = Poly(self.n, self.q)
                c.cofficient = [(x+y) % self.q for x, y in zip(self.cofficient, other.cofficient)]
                return c
        elif type(other) is int:
                c = deepcopy(self)
                c.cofficient[0] = (c.cofficient[0] + other) % self.q
                return c

    __radd__ = __add__

    def __sub__(self, other):
        if self.q != other.q:
            raise Exception("Polynomial Addiditon: Inputs must have the same modulus")
        else:
            c = Poly(self.n, self.q)
            c.cofficient = [(x-y) % self.q for x, y in zip(self.cofficient, other.cofficient)]

        return c

    def __mod__(self, other):
        c = Poly(self.n, self.q)
        c.cofficient = [x % other for x in self.cofficient]
        return c

    def __mul__(self, other):
        c = Poly(self.n, self.q)
        if type(other) is Poly:
            for i in range(self.n):
                for j in range(self.n):
                    if i + j >= self.n:
                        c.cofficient[i + j - self.n] -= self.cofficient[i] * other.cofficient[j]
                    else:
                        c.cofficient[i + j] += self.cofficient[i] * other.cofficient[j]
        elif type(other) is int:
            for i in range(c.n):
                c.cofficient[i] = self.cofficient[i] * other

        return c

    __rmul__ = __mul__
