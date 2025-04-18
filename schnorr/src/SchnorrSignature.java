import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class SchnorrSignature {

    static SecureRandom random = new SecureRandom();
    private int q_len;
    private int p_len;
    private int g_len;

    public SchnorrSignature(int number) {
        switch(number){
            case 1:
                q_len = 158;
                p_len = 2174;
                g_len = 2174;
                break;
            case 2:
                q_len = 170;
                p_len = 1538;
                g_len = 1538;
                break;
            case 3:
                q_len = 256;
                p_len = 3072;
                g_len = 3072;
                break;
            case 4:
                q_len = 224;
                p_len = 2048;
                g_len = 2048;
                break;
            case 5:
                q_len = 200;
                p_len = 2048;
                g_len = 2048;
                break;
            case 6:
                q_len = 250;
                p_len = 3000;
                g_len = 3000;
                break;
            default:
                throw new IllegalArgumentException("Upisan neispravan broj");
        }
    }

    public User generateKeys(){
        BigInteger p;
        BigInteger q = BigInteger.probablePrime(q_len, random);
        BigInteger k;
        BigInteger g = BigInteger.probablePrime(g_len, random);
        BigInteger alpha;
        BigInteger a;
        BigInteger y;

        //dijeli li q vrijednost (p-1)?
        // k = (p-1)/q, k*q+1 = p
        while(true){
            k = new BigInteger(p_len-q_len, random);
            p = k.multiply(q).add(BigInteger.ONE);
            if(p.isProbablePrime(100))
                break;
        }

        /*System.out.println("q: "+q);
        System.out.println("p: "+p);
        System.out.println("g: "+g);*/

        for(alpha = g.modPow(p.subtract(BigInteger.ONE).divide(q), p); alpha.equals(BigInteger.ONE); alpha.equals(BigInteger.ONE)); alpha = g.modPow(p.subtract(BigInteger.ONE).divide(q), p);

        //System.out.println("alpha: "+alpha);

        while (true){
            a = new BigInteger(q_len, random);
            if(a.compareTo(BigInteger.ONE) >= 0 && (q.subtract(BigInteger.ONE)).compareTo(a) >= 0){}
                break;
        }

        //System.out.println("a: "+a);

        y = alpha.modPow(a, p);

        //System.out.println("y: "+y);

        PublicKey publicKey = new PublicKey(p,q,alpha,y);
        PrivateKey privateKey = new PrivateKey(a);
        return new User(privateKey,publicKey);

    }


    public static BigInteger hash(String message, BigInteger addon) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] addonBytes = addon.toByteArray();
        byte[] combined = new byte[message.length()+addonBytes.length];
        System.arraycopy(message.getBytes(StandardCharsets.UTF_8), 0, combined, 0, message.length());
        System.arraycopy(addonBytes, 0, combined, message.length(), addonBytes.length);
        BigInteger hash = new BigInteger(1, md.digest(combined));
        //System.out.println("Hash: " + hash.toString(16));
        return hash;
    }


    public Signature generateSignature(String message, User user) throws NoSuchAlgorithmException {
        PrivateKey privateKey = user.privateKey;
        PublicKey publicKey = user.publicKey;
        BigInteger k;
        while (true){
            k = new BigInteger(q_len, random);
            if(k.compareTo(BigInteger.ONE) >= 0 && (publicKey.q.subtract(BigInteger.ONE)).compareTo(k) >= 0)
                break;
        }

        BigInteger r = publicKey.alpha.modPow(k,publicKey.p);
        //System.out.println("r: " + r);
        BigInteger e = hash(message,r);
        //System.out.println("e: " + e);
        BigInteger s = privateKey.a.multiply(e).add(k).mod(publicKey.q);
        //System.out.println("s: " + s);

        return new Signature(s,e);
    }


    public boolean verifySignature(String message, Signature signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //System.out.println("Verifying signature...");
        BigInteger alphaPowerS = publicKey.alpha.modPow(signature.s,publicKey.p);
        //System.out.println("alpha^s mod p: " + alphaPowerS);
        BigInteger yPowerE = publicKey.y.modPow(signature.e,publicKey.p);
        //System.out.println("y^e mod p: " + yPowerE);
        BigInteger yPowerNegativeE = yPowerE.modInverse(publicKey.p);
        //System.out.println("y^(-e) mod p (inverse): " + yPowerNegativeE);
        BigInteger v = alphaPowerS.multiply(yPowerNegativeE).mod(publicKey.p);
        //System.out.println("v: " + v);
        BigInteger e = hash(message,v);
        //System.out.println("e: " + e);
        return e.equals(signature.e);
    }

    public Signature generateAgregateSignature(List<User> users, String message) throws NoSuchAlgorithmException {
        BigInteger R = BigInteger.ONE;
        BigInteger S = BigInteger.ZERO;
        List<BigInteger> klist = new ArrayList<>();

        for(User user : users){
            PrivateKey privateKey = user.privateKey;
            PublicKey publicKey = user.publicKey;
            BigInteger k;

            while (true){
                k = new BigInteger(q_len, random);
                if(k.compareTo(BigInteger.ONE) >= 0 && (publicKey.q.subtract(BigInteger.ONE)).compareTo(k) >= 0)
                    break;
            }
            klist.add(k);
            BigInteger r = publicKey.alpha.modPow(k,publicKey.p);
            R = R.multiply(r).mod(publicKey.p);
        }
        BigInteger e = hash(message,R);

        for(int i = 0; i < users.size(); i++) {
            User user = users.get(i);
            PrivateKey privateKey = user.privateKey;
            PublicKey publicKey = user.publicKey;
            BigInteger k = klist.get(i);

            BigInteger s =privateKey.a.multiply(e).add(k).mod(publicKey.q);
            S = S.add(s).mod(publicKey.q);
        }
        return new Signature(S,e);
    }

    public List<User> generateMultipleKeys(int n) {
        BigInteger p;
        BigInteger q = BigInteger.probablePrime(q_len, random);
        BigInteger k;
        BigInteger g = BigInteger.probablePrime(g_len, random);
        BigInteger alpha;
        BigInteger a;
        BigInteger y;
        List<User> users = new ArrayList<>();
        while(true){
            k = new BigInteger(p_len-q_len, random);
            p = k.multiply(q).add(BigInteger.ONE);
            if(p.isProbablePrime(100))
                break;
        }
        for(alpha = g.modPow(p.subtract(BigInteger.ONE).divide(q), p); alpha.equals(BigInteger.ONE); alpha.equals(BigInteger.ONE)); alpha = g.modPow(p.subtract(BigInteger.ONE).divide(q), p);

        for(int i = 0; i < n; i++){
            while (true){
                a = new BigInteger(q.bitLength(), random);
                if(a.compareTo(BigInteger.ONE) >= 0 && (q.subtract(BigInteger.ONE)).compareTo(a) >= 0){}
                    break;
            }

            y = alpha.modPow(a, p);

            PublicKey publicKey = new PublicKey(p,q,alpha,y);
            PrivateKey privateKey = new PrivateKey(a);
            User u = new User(privateKey,publicKey);
            users.add(u);
        }
        return users;

    }
    public boolean verifyAgregateSignature(List<User> users, Signature signature, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        User user = users.get(0);
        PublicKey publicKey = user.publicKey;
        BigInteger y = BigInteger.ONE;
        for(User u: users){
            y = y.multiply(u.publicKey.y);
        }
        y = y.mod(user.publicKey.p);

        BigInteger alphaPowerS = publicKey.alpha.modPow(signature.s,publicKey.p);
        BigInteger yPowerE = y.modPow(signature.e,publicKey.p);
        BigInteger yPowerNegativeE = yPowerE.modInverse(publicKey.p);
        BigInteger v = alphaPowerS.multiply(yPowerNegativeE).mod(publicKey.p);

        BigInteger e = hash(message,v);
        return e.equals(signature.e);

    }


    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        StringBuilder sb = new StringBuilder();
        Scanner sc = new Scanner(System.in);
        sb.append("[1]Lenstra/Verheul(2025) Key:158 Group:2174");
        sb.append("\n[2]Lenstra Updated(2025) Key:170 Group:1538");
        sb.append("\n[3]ECRYPT(2018-2028) Key:256 Group:3072");
        sb.append("\n[4]NIST(2019-2030) Key:224 Group:2048");
        sb.append("\n[5]ANSSI(2021-2030) Key:200 Group:2048");
        sb.append("\n[6]BSI(2023-2026) Key:250 Group:3000");
        int broj;
        while(true){
            System.out.println(sb.toString());
            System.out.println("Unesite broj za standard generiranja ključeva:");
            if(sc.hasNextInt()){
                broj = sc.nextInt();
                if(broj>=1&&broj<=6){
                    System.out.println("Uspjeh!");
                    break;
                }
                else{
                    System.out.println("Neispravan broj, pokušajte ponovo.");
                }
            }else{
                sc.next();
            }
        }

        SchnorrSignature sp = new SchnorrSignature(broj);

        User user1 = sp.generateKeys();
        //System.out.println(user1);
        String message = "Jesi l živa, staričice moja?";
        Signature signature1 = sp.generateSignature(message, user1);
        System.out.println(sp.verifySignature(message, signature1, user1.publicKey));

        List<User> users = sp.generateMultipleKeys(5);
        Signature signature2 = sp.generateAgregateSignature(users, message);
        System.out.println(sp.verifyAgregateSignature(users, signature2, message));

    }
}
