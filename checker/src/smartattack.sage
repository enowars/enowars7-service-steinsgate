def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

import sys

q = 0xc00000000000000000000000000000228000000000000000000000000000018d
curve = EllipticCurve(GF(q), [0, 0xcd080])
G = curve((0xb044bc1fa42ca2f1d7d88e9dd22b79f0f1277b94804c1d2f7098dceaf01fc4a8, 0x8f2a2d6fe3550e8b6749fc4ad5fa804f941b5eedc115dd54f1b34df2b964dcf6))

if len(sys.argv) < 3:
    print("Please enter all parameters")
    exit(1)
P = curve((int(sys.argv[1]), int(sys.argv[2])))

privkey = SmartAttack(G, P, q)

response = []
response.append(privkey)
for i in range(1,9):
    response.append(q*i + privkey)

print(response)
