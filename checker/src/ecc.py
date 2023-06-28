import collections

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> assert n * inv(n, q) % q == 1
    """
    for i in range(q):
        if (n * i) % q == 1:
            return i
        pass
    assert False, "unreached"
    pass

def sqrt(n, q):
    """sqrt on PN modulo: it may not exist
    >>> assert (sqrt(n, q) ** 2) % q == n
    """
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")


Coord = collections.namedtuple("Coord", ["x", "y"])

class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: int < q
        - returns: ((x, y), (x,-y)) or not found exception
        >>> a, ma = ec.at(x)
        >>> assert a.x == ma.x and a.x == x
        >>> assert a.x == ma.x and a.x == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>>  c = ec.add(a, b)
        >>> assert ec.is_valid(a)
        >>> assert ec.add(c, ec.neg(b)) == a
        """
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and p1.y != p2.y:
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(n, p)
        >>> assert ec.is_valid(m)
        """
        r = self.zero
        for i in range(n):
            r = self.add(r, p)
            pass
        return r
    pass
