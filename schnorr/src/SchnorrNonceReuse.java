import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public final class SchnorrNonceReuse {

    private SchnorrNonceReuse() {}


    public static BigInteger recoverR(String message, Signature signature, PublicKey publicKey)
            throws NoSuchAlgorithmException {

        BigInteger alphaPowerS = publicKey.alpha.modPow(signature.s, publicKey.p);
        BigInteger yPowerE = publicKey.y.modPow(signature.e, publicKey.p);
        BigInteger yPowerNegativeE = yPowerE.modInverse(publicKey.p);

        BigInteger r = alphaPowerS.multiply(yPowerNegativeE).mod(publicKey.p);


        BigInteger eCheck = SchnorrSignature.hash(message, r);
        if (!eCheck.equals(signature.e)) {
            throw new IllegalArgumentException("Potpis nije valjan za zadanu poruku (e != H(m||r)).");
        }
        return r;
    }



    public static PrivateKey recoverPrivateKeyFromNonceReuse(
            String m1, Signature signature1,
            String m2, Signature signature2,
            PublicKey publicKey) throws NoSuchAlgorithmException {

        BigInteger r1 = recoverR(m1, signature1, publicKey);
        BigInteger r2 = recoverR(m2, signature2, publicKey);

        if (!r1.equals(r2)) {
            throw new IllegalArgumentException("Nema nonce-reuse (r1 != r2) - napad se ne može primijeniti.");
        }

        BigInteger q = publicKey.q;

        BigInteger num = signature1.s.subtract(signature2.s).mod(q); // (s1 - s2) mod q
        BigInteger den = signature1.e.subtract(signature2.e).mod(q); // (e1 - e2) mod q

        if (den.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("e1 == e2 (mod q) — nema mod inverza, napad ne radi.");
        }

        BigInteger a = num.multiply(den.modInverse(q)).mod(q);
        return new PrivateKey(a);
    }
}