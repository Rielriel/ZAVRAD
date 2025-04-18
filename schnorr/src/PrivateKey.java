import java.math.BigInteger;

public class PrivateKey {
    public BigInteger a;

    public PrivateKey(BigInteger a) {
        this.a = a;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("PrivateKey{");
        sb.append("a=").append(a);
        sb.append('}');
        return sb.toString();
    }
}
