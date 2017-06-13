package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade;

import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.*;

/**
 * Created by Alisson on 14/04/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * * Bob
 * 1. Selecionar Arquivo
 * 2. Ler Arquivo
 * 3. Gerar Par de Chaves
 * 4. Criar Hash do arquivo
 * 5. Recebe chave pública da Alice
 * 6. Criptografa hash com chave provada do Bob
 * 7. Criar chave de sessão para arquivo
 * 8. Criptografa arquivo com chave de sessão
 * 9. Criptografa chave de sessão com chave pública da Alice
 * 10. Envia para Alice (Arquivo, chave de sessão, hash - Criptografados) e chave pública do Bob.
 * 11. Fecha conexão
 */
public class Bob {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException{

        JFileChooser chooserArquivo = new JFileChooser();
        int escolha = chooserArquivo.showOpenDialog(new JFrame());
        if (escolha != JFileChooser.APPROVE_OPTION) {
            return;
        }
        System.out.println("1. Selecionou arquivo.");

        //2. Ler o arquivo
        System.out.println("2. Lendo o arquivo...");
        File arquivo = new File(chooserArquivo.getSelectedFile().getAbsolutePath());
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] barquivo = new byte[(int) fin.getChannel().size()];
        fin.read(barquivo);
        System.out.println("2.1 Leu o arquivo.");

        //3. Gerar par de chaves
        System.out.println("3. Gerar par de chaves...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair kp = keyGen.generateKeyPair();
        System.out.println("3.1 Gerou par de chaves");

        //4. Aplicar Hash no Arquivo
        System.out.println("4. Aplicar Hash no Arquivo.");
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hash = md.digest(barquivo);
        System.out.println("4.1 Hash Aplicado.");

        //5. Receber a chave pública da Alice
        // Conectar à Alice
        System.out.println("5. Conectar à Alice...");
        Socket s = new Socket("localhost", 3333);
        System.out.println("5.1 Conectou...");

        ObjectInputStream in = new ObjectInputStream(s.getInputStream());
        ObjetoTroca obj = (ObjetoTroca) in.readObject();
        System.out.println("5.2 Recebeu a chave pública da Alice...");

        //6. Criar o Criptador e Criptografar Hash
        System.out.println("6. Criar criptador com a Chave Privada de Bob...");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPrivate());
        System.out.println("6.1 Criptador criado...");

        System.out.println("6.2. Iniciando criptografia do Hash...");
        byte[] b_hash = cipher.doFinal(hash);
        System.out.println("6.3. Criptografou o Hash.");

        //7. Criar a chave de sessão
        System.out.println("7. Criando chave de sessão...");
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey keySessao = kgen.generateKey();
        byte[] chaveSessao = keySessao.getEncoded();
        System.out.println("7.1 Criou chave de sessão");

        //8. Criar Criptador e Criptografar o arquivo com a chave de sessão
        System.out.println("8. Criptograr o arquivo com a chave de sessão...");
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySessao);
        System.out.println("8.1 Criou o criptador de sessão");

        System.out.println("8.2. Iniciando criptografia do arquivo...");
        byte[] b_cripto = cipher.doFinal(barquivo);
        System.out.println("8.3. Criptografou o arquivo.");

        //9. Criptografar chave de sessão com a chave pública de Alice
        System.out.println("9. Criptografar chave de sessão...");
        ObjetoTroca objeto = new ObjetoTroca();
        objeto.setNomeArquivo(chooserArquivo.getSelectedFile().getName());

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, obj.getChavePublica());

        byte[] k_cripto = cipher.doFinal(chaveSessao);
        objeto.setChaveSessao(k_cripto);
        objeto.setArquivo(b_cripto);
        objeto.setChavePublica(kp.getPublic());
        objeto.setAssinatura(b_hash);
        System.out.println("9.1 Criptografou o arquivo e chave de sessão...");

        //10. Enviar o arquivo para Alice
        System.out.println("10. Enviar dados para Alice.");
        System.out.println("10.1. Enviando...");
        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.writeObject(objeto);
        out.close();
        s.close();
        System.out.println("10.2. Envio concluído.");
        System.out.println("11. Fechando conexão...");


        System.exit(0);
    }
}
