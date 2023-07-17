class Point(object):
    #Construct a point with two given coordindates.
    def __init__(self, x, y):
        self.x, self.y = x, y
        self.inf = False

    #Construct the point at infinity.
    @classmethod
    def atInfinity(cls):
        P = cls(0, 0)
        P.inf = True
        return P

    def __str__(self):
        if self.inf:
            return 'Inf'
        else:
            return '(' + str(self.x) + ',' + str(self.y) + ')'

    def __eq__(self,other):
        if self.inf:
            return other.inf
        elif other.inf:
            return self.inf
        else:
            return self.x == other.x and self.y == other.y

    def is_infinite(self):
        return self.inf

class Curve(object):
    def __init__(self, a, b, c, char, exp):
        self.a, self.b, self.c = a, b, c
        self.char, self.exp = char, exp
        print(self)
    #Compute the discriminant.
    def discriminant(self):
        a, b, c = self.a, self.b, self.c
        return -4*a*a*a*c + a*a*b*b + 18*a*b*c - 4*b*b*b - 27*c*c

    #Compute the order of a point on the curve.
    def order(self, P):
        Q = P
        orderP = 1
        #Add P to Q repeatedly until obtaining the identity (point at infinity).
        while not Q.is_infinite():
            Q = self.add(P,Q)
            orderP += 1
        return orderP

    #List all multiples of a point on the curve.
    def generate(self, P):
        Q = P
        orbit = [str(Point.atInfinity())]
        #Repeatedly add P to Q, appending each (pretty printed) result.
        while not Q.is_infinite():
            orbit.append(str(Q))
            Q = self.add(P,Q)
        return orbit

    #Double a point on the curve.
    def double(self, P):
        return self.add(P,P)

    #Add P to itself k times.
    def mult(self, P, k):
        if P.is_infinite():
            return P
        elif k == 0:
            return Point.atInfinity()
        elif k < 0:
            return self.mult(self.invert(P), -k)
        else:
            #Convert k to a bitstring and use peasant multiplication to compute the product quickly.
            b = bin(k)[2:]
            return self.repeat_additions(P, b, 1)

    #Add efficiently by repeatedly doubling the given point, and adding the result to a running
    #total when, after the ith doubling, the ith digit in the bitstring b is a one.
    def repeat_additions(self, P, b, n):
        if b == '0':
            return Point.atInfinity()
        elif b == '1':
            return P
        elif b[-1] == '0':
            return self.repeat_additions(self.double(P), b[:-1], n+1)
        elif b[-1] == '1':
            return self.add(P, self.repeat_additions(self.double(P), b[:-1], n+1))

    #Returns a pretty printed list of points.
    def show_points(self):
        return [str(P) for P in self.get_points()]

class CurveOverFp(Curve):
    #Construct a Weierstrass cubic y^2 = x^3 + ax^2 + bx + c over Fp.
    def __init__(self, a, b, c, p):
        Curve.__init__(self, a, b, c, p, 1)

    def contains(self, P):
        if P.is_infinite():
            return True
        else:
            return (P.y*P.y) % self.char == (P.x*P.x*P.x + self.a*P.x*P.x + self.b*P.x + self.c) % self.char

    def get_points(self):
        #Start with the point at infinity.
        points = [Point.atInfinity()]

        #Just brute force the rest.
        for x in range(self.char):
                for y in range(self.char):
                    P = Point(x,y)
                    if (y*y) % self.char == (x*x*x + self.a*x*x + self.b*x + self.c) % self.char:
                        points.append(P)
        return points

    def invert(self, P):
        if P.is_infinite():
            return P
        else:
            return Point(P.x, -P.y % self.char)

    def add(self, P_1, P_2):
        #Adding points over Fp and can be done in exactly the same way as adding over Q,
        #but with of the all arithmetic now happening in Fp.
        y_diff = (P_2.y - P_1.y) % self.char
        x_diff = (P_2.x - P_1.x) % self.char
        if P_1.is_infinite():
            return P_2
        elif P_2.is_infinite():
            return P_1
        elif x_diff == 0 and y_diff != 0:
            return Point.atInfinity()
        elif x_diff == 0 and y_diff == 0:
            if P_1.y == 0:
                return Point.atInfinity()
            else:
                ld = ((3*P_1.x*P_1.x + 2*self.a*P_1.x + self.b) * mult_inv(2*P_1.y, self.char)) % self.char
        else:
            ld = (y_diff * mult_inv(x_diff, self.char)) % self.char
        nu = (P_1.y - ld*P_1.x) % self.char
        x = (ld*ld - self.a - P_1.x - P_2.x) % self.char
        y = (-ld*x - nu) % self.char
        return Point(x,y)

#Extended Euclidean algorithm.
def euclid(sml, big):
    #When the smaller value is zero, it's done, gcd = b = 0*sml + 1*big.
    if sml == 0:
        return (big, 0, 1)
    else:
        #Repeat with sml and the remainder, big%sml.
        g, y, x = euclid(big % sml, sml)
        #Backtrack through the calculation, rewriting the gcd as we go. From the values just
        #returned above, we have gcd = y*(big%sml) + x*sml, and rewriting big%sml we obtain
        #gcd = y*(big - (big//sml)*sml) + x*sml = (x - (big//sml)*y)*sml + y*big.
        return (g, x - (big//sml)*y, y)

#Compute the multiplicative inverse mod n of a with 0 < a < n.
def mult_inv(a, n):
    g, x, y = euclid(a, n)
    #If gcd(a,n) is not one, then a has no multiplicative inverse.
    if g != 1:
        raise ValueError('multiplicative inverse does not exist')
    #If gcd(a,n) = 1, and gcd(a,n) = x*a + y*n, x is the multiplicative inverse of a.
    else:
        return x % n

from sage.all import Qp, ZZ, GF, EllipticCurve

def _lift(E, P, gf):
    x, y = map(ZZ, P.xy())
    for point_ in E.lift_x(x, all=True):
        _, y_ = map(gf, point_.xy())
        if y == y_:
            return point_

q = 0xc00000000000000000000000000000228000000000000000000000000000018d
gf = GF(q)
Gl_curve = EllipticCurve(gf, [0, 0xcd080])
Gl_G = Gl_curve((0xb044bc1fa42ca2f1d7d88e9dd22b79f0f1277b94804c1d2f7098dceaf01fc4a8, 0x8f2a2d6fe3550e8b6749fc4ad5fa804f941b5eedc115dd54f1b34df2b964dcf6))

def attack(xx, yy):
    global gf, Gl_G
    P = Gl_curve((xx, yy))
    p = gf.order()
    E = EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in Gl_curve.a_invariants()])
    G = p * _lift(E, Gl_G, gf)
    P = p * _lift(E, P, gf)
    Gx, Gy = G.xy()
    Px, Py = P.xy()
    privkey = int(gf((Px / Py) / (Gx / Gy)))
    response = []
    response.append(privkey)
    for i in range(1,9):
        response.append(q*i + privkey)
    return response

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Please enter all parameters")
        exit(1)

    P = Gl_curve((int(sys.argv[1]), int(sys.argv[2])))

    privkey = attack(P.xy()[0], P.xy()[1])
    print(privkey)
