/*
    Nathan Gibson
    3-14-2017
    This program demonstrates the RSA encryption algorithm using sockets in Java
*/
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;
import java.net.*;
import java.io.*;
/*
    Class acts as a data structure for storing a key, including exponent and modulus
*/
class Key{
    BigInteger exponent;
    BigInteger modulus;

    public Key(BigInteger e, BigInteger m){
        this.exponent = e;
        this.modulus = m;
    }
}
/*
    Class acts as a data structure for storing a pair of keys
*/
class KeyPair{
    Key pub;
    Key priv;

    public KeyPair(Key pub, Key priv){
        this.pub = pub;
        this.priv = priv;
    }
}
/*
    Class holds all of the functionality related to the RSA algorithm
    decoupling it from the server implementation
*/
class RSA{
    /*
        This method requires a length for the key that you want to generate. It uses the BigInteger class
        to find two primes and uses these primes in the RSA algorithm, returning a KeyPair
    */
    public KeyPair generateKey(int len){
        SecureRandom rnd = new SecureRandom();
        BigInteger p =  new BigInteger(len, 100, rnd);
        System.out.println("[+] p = " + p.toString());
        BigInteger q = new BigInteger(len, 100, rnd);
        System.out.println("[+] q = " + q.toString());
        BigInteger n = p.multiply(q);
        System.out.println("[+] n = " + n.toString());
        BigInteger phi = p.subtract(BigInteger.valueOf(1)).multiply(q.subtract(BigInteger.valueOf(1)));
        System.out.println("[+] phi = " + phi.toString());
        BigInteger e = findE(phi);
        System.out.println("[+] e = " + e.toString());
        BigInteger d = e.modInverse(phi);
        System.out.println("[+] d = " + d.toString());
        return new KeyPair(new Key(e, n), new Key(d, n));
    }
    /*
        This function will provided phi, find a suitable exponent. If this cannot be found, it causes the program
        to terminate
    */
    private BigInteger findE(BigInteger phi){
        for (BigInteger counter = BigInteger.valueOf(2); counter.compareTo(phi) < 0; counter = counter.add(BigInteger.ONE)) {
            if(phi.gcd(counter).compareTo(BigInteger.valueOf(1)) == 0) {
                return counter;
            }
        }   
        System.err.println("[+] value for E not found...");
        System.exit(1);
        return null;
    }
    /*
        This method will decrypt a ciphertext c, provided a modulus d and an exponent n
    */
    public static BigInteger decrypt(BigInteger d, BigInteger n, BigInteger c){
        return c.modPow(d, n);
    }
}
/*
    This class provides the functionality for the server. The protocol is as follows:

    1.Wait for a client to connect
    Upon connection:
    2.Send the connected client the exponent portion of the public key
    3.Send the modulus portion of the public key
    4.Receive the ciphertext from the client
    5.Decrypt the ciphertext and print the plaintext to stdout on the server
*/

public class Server{

    static final int SERVER_PORT = 4567;

    public static void main(String[] args) throws IOException, ClassNotFoundException{
        RSA rsa = new RSA();
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter key size: ");
        int keysize = sc.nextInt();
        long startTime;
        long endTime;

        //generate keys
        startTime = System.nanoTime();
        KeyPair kp = rsa.generateKey(keysize);
        endTime = System.nanoTime();
        System.out.println ("[+] took " + (endTime - startTime) + " ns to generate keys");

        System.out.println("[+] starting a server on port: " + SERVER_PORT);
        ServerSocket serverSocket = null; 
        try { 
            serverSocket = new ServerSocket(SERVER_PORT); 
        } catch (IOException e) { 
            System.err.println("[+] could not listen on specified port"); 
            System.exit(1); 
        } 

        Socket clientSocket = null; 
        System.out.println ("[+] waiting for connection");

        try { 
            clientSocket = serverSocket.accept(); 
        } catch (IOException e){ 
            System.err.println("[+] connection failed"); 
            System.exit(1); 
        } 

        System.out.println("[+] connection recieved from: " + clientSocket.getInetAddress());

        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream()); 
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream()); 

        System.out.println("[+] sending exponent");
        out.writeObject(kp.pub.exponent);

        System.out.println("[+] sending n");
        out.writeObject(kp.pub.modulus);

        //read the object representing the cipher from the client
        BigInteger cipher = null;
        Object object = in.readObject();
        if(object instanceof BigInteger) {
             cipher = (BigInteger)object;
        }
        System.out.println("[+] server received cipher: " + cipher.toString());

        //decrypt cipher and display the plaintext
        startTime = System.nanoTime();
        BigInteger plainText = rsa.decrypt(kp.priv.exponent, kp.priv.modulus, cipher);
        endTime = System.nanoTime();
        System.out.println ("[+] took " + (endTime - startTime) + " ns to decrypt cipher");
        System.out.println("[+] decrypted cipher is: " + plainText.toString());

        in.close();
        out.close();
        clientSocket.close(); 
        serverSocket.close(); 
        System.out.println("[+] server stopped");
    }
}