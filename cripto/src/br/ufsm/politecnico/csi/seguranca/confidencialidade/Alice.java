package br.ufsm.politecnico.csi.seguranca.confidencialidade;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

/**
 * Created by cpol on 27/03/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * Alice
 * 1: Abrir ServerSocket();
 * 2. Gerar par de chaves
 * 3. Aguardar conexão
 * 4: Enviar chave publica
 * 5: Receber arquivo e chave de sessão
 * 6: Decifrar a chave de sessão
 * 7: Decifrar o arquivo com a chave de sessão
 * 8: Fechar conexão
 * 9: Salvar arquivo
 */
public class Alice {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        System.out.println("1. Abrir ServerSocket...");
        ServerSocket ss = new ServerSocket(3333);

        System.out.println("2. Criar par de chaves...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(8000);
        KeyPair kp = keyGen.generateKeyPair();
        System.out.println("2.1 Criou par de chaves");

        while (true) {
            System.out.println("3. Aguardando conexões na porta 3333...");
            Socket s = ss.accept();
            System.out.println("3.1. Cliente conectado.");

            //Enviando a chave publica
            System.out.println("4. Enviando chave Pública...");
            ObjetoTroca obj = new ObjetoTroca();
            obj.setChavePublica(kp.getPublic());
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            out.writeObject(obj);
            out.flush();
            System.out.println("4.1 Chave enviada...");

            //2. Lendo o arquivo do socket
            System.out.println("5. Lendo o socket...");
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            ObjetoTroca objetoTroca = (ObjetoTroca) in.readObject();
            System.out.println("5.1 Leu o arquivo do socket.");

            //4. Criar o desencriptador
            System.out.println("6. Criar desencriptador da chave de sessão...");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            System.out.println("6.1 Criou o desencriptador da chave de sessão.");

            //5. Descriptografar chave de sessão
            System.out.println("7. Iniciando descriptografia da chave de sessão...");
            byte[] kSessao = cipher.doFinal(objetoTroca.getChaveSessao());
            System.out.println("7.1 Descriptografou chave de sessão.");

            // Criação da SecretKey com a chave de sessão e decrifrar o arquivo
            System.out.println("8. Criação da SecretKey com a chave de sessão...");
            cipher = Cipher.getInstance("AES");
            SecretKey k_sessao = new SecretKeySpec(kSessao, 0, kSessao.length, "AES");
            System.out.println("8.1 Chave criada com sucesso.");
            System.out.println("9 Descriptografar arquivo.");
            cipher.init(Cipher.DECRYPT_MODE, k_sessao);
            byte[] b_arquivo = cipher.doFinal(objetoTroca.getArquivo());
            System.out.println("9.1 Arquivo descriptografado.");

            //6. Escrever o arquivo
            System.out.println("10. Escrevendo o arquivo descriptografado.");
            File saida = new File(objetoTroca.getNomeArquivo());
            OutputStream fout = new FileOutputStream(saida);
            fout.write(b_arquivo);
            fout.close();
            s.close();
            System.out.println("11. Concluído, arquivo salvo..\n");
        }
    }
}