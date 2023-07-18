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
