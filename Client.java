/*
    Nathan Gibson
    3-14-2017
    This program demonstrates the RSA encryption algorithm using sockets in Java
*/
import java.math.BigInteger;
import java.util.Scanner;
import java.util.Random;
import java.io.*;
import java.net.*;
/*
    This class handles communication to the server, the protocol is as follows:
    1.Wait until a connection is made to the server
    2.Receive e from the server
    3.Receive n from the server
    4.Use e and n to encrypt a message entered by the user
    5.Send that encrypted message to the server
*/
public class Client{

    public static final String SERVER_IP = "127.0.0.1";
    public static final int SERVER_PORT = 4567;
    /*
        function handles the encryption of a message m given an exponent e and a modulus n
    */
    public static BigInteger encrypt(BigInteger e, BigInteger n, BigInteger m){
        if(m.compareTo(n) > 0){
            System.err.println("[+] input is too large");
            System.exit(1);
        }
        return m.modPow(e, n);
    }
   
    public static void main(String[] args) throws IOException, InterruptedException, ClassNotFoundException{
        Socket socket = null;
        ObjectOutputStream  out = null;
        ObjectInputStream  in = null;
        boolean connected = false;
        Random rand = new Random();

        //keep looping until we get a connection, sleeping for 2 seconds
        System.out.println("[+] attempting to connect to " + SERVER_IP + " on port " + SERVER_PORT);
        while(connected == false){
            try {
                socket = new Socket(SERVER_IP, SERVER_PORT);
                out = new ObjectOutputStream(socket.getOutputStream()); 
                in = new ObjectInputStream(socket.getInputStream()); 
                connected = true;
            } catch (Exception e) {
                System.err.println("[+] waiting for server");
                Thread.sleep(2000);
            }
        }

        System.out.println("[+] client connected to server");

        BigInteger exponent = null;
        BigInteger n = null;

        //read exponent from server
        Object object = in.readObject();
        if(object instanceof BigInteger) {
             exponent = (BigInteger)object;
        }

        System.out.println("[+] client received e = " + exponent + " from server");

        //read modulus from server
        object = in.readObject();
        if(object instanceof BigInteger) {
             n = (BigInteger)object;
        }
        System.out.println("[+] client received n = " + n + " from server");

        //calculate message to send
        BigInteger message = new BigInteger(n.bitLength(), rand);
        while(message.compareTo(n) > -1){
            message = message.subtract(BigInteger.ONE);
        }
        System.out.println("[+] message: " + message.toString());

        //encrypt using parameters from the server
        long startTime = System.nanoTime();
        BigInteger cipher = encrypt(exponent, n, message);
        long endTime = System.nanoTime();
        System.out.println ("[+] took " + (endTime - startTime) + " ns to encrypt plaintext");
        System.out.println("[+] encrypted message: " + cipher.toString());

        //send the ciphertext to the server
        System.out.println("[+] sending cipher to server");
        out.writeObject(cipher);

        out.close();
        in.close();
        socket.close();
        System.out.println("[+] connection closed");
    }
}