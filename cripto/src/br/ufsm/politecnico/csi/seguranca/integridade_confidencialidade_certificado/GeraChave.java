package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade_certificado;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by cpol on 17/04/2017.
 */
public class GeraChave  {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {


        // 1. Gerar par chave
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        // 2. Gera par de chaves Bob
        KeyPair kp_Bob = keyGen.generateKeyPair();
        System.out.println("2. Par de chaves gerado(Bob).");

        // 3. Gera par de chaves Alice
        KeyPair kp_Alice = keyGen.generateKeyPair();
        System.out.println("3. Par de chaves gerado(Alice).");

        //4. Salvando chave publica Bob
        System.out.println("4. Salvando chave publica Bob");
        File chavePubBob = new File("chavePubBob.key");
        OutputStream outChavePubBob = new FileOutputStream(chavePubBob);
        outChavePubBob.write(kp_Bob.getPublic().getEncoded());
        outChavePubBob.close();

        //5. Salvando chave privada Bob
        System.out.println("5. Salvando chave privada Bob");
        File chavePrivBob = new File("chavePrivBob.key");
        OutputStream outChavePrivBob = new FileOutputStream(chavePrivBob);
        outChavePrivBob.write(kp_Bob.getPrivate().getEncoded());
        outChavePrivBob.close();

        //6. Salvando chave publica Alice
        System.out.println("6. Salvando chave publica Alice");
        File chavePubAlice = new File("chavePubAlice.key");
        OutputStream outChavePubAlice = new FileOutputStream(chavePubAlice);
        outChavePubAlice.write(kp_Alice.getPublic().getEncoded());
        outChavePubAlice.close();

        //7. Salvando chave privada Alice
        System.out.println("7. Salvando chave privada Alice");
        File chavePrivAlice = new File("chavePrivAlice.key");
        OutputStream outChavePrivAlice = new FileOutputStream(chavePrivAlice);
        outChavePrivAlice.write(kp_Alice.getPrivate().getEncoded());
        outChavePrivAlice.close();



    }

}
