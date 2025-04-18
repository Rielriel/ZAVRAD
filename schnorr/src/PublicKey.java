import java.math.BigInteger;
import java.util.Objects;

public class PublicKey {
    public BigInteger p, q, alpha, y;

    public PublicKey(BigInteger p, BigInteger q, BigInteger alpha, BigInteger y) {
        this.p = p;
        this.q = q;
        this.alpha = alpha;
        this.y = y;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PublicKey publicKey = (PublicKey) o;
        return Objects.equals(p, publicKey.p) && Objects.equals(q, publicKey.q) && Objects.equals(alpha, publicKey.alpha) && Objects.equals(y, publicKey.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, q, alpha, y);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("PublicKey{");
        sb.append("p=").append(p);
        sb.append(", q=").append(q);
        sb.append(", alpha=").append(alpha);
        sb.append(", y=").append(y);
        sb.append('}');
        return sb.toString();
    }
}
