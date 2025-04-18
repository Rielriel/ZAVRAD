import java.math.BigInteger;

public class User {
    public PrivateKey privateKey;
    public PublicKey publicKey;


    public User(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("User{");
        sb.append("privateKey=").append(privateKey);
        sb.append(", publicKey=").append(publicKey);
        sb.append('}');
        return sb.toString();
    }
}
