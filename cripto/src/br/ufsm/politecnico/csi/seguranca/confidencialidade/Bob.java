package br.ufsm.politecnico.csi.seguranca.confidencialidade;

import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by cpol on 22/03/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * Bob:
 * 1: Selecionar arquivo
 * 2: Ler o arquivo
 * 3: Conectar Alice
 * 4: Receber chave pública
 * 5: Criar a chave de sessão
 * 6: Criptografar arquivo com a chave de sessão
 * 7: Criptografa chave de sessão com a chave publica
 * 8: Envia arquivo e chave de sessão criptografado
 * 9: Fecha conexão
 */
public class Bob {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
        //1. Selecionar o arquivo
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

        //3. Conectar à Alice
        Socket s = new Socket("localhost", 3333);
        System.out.println("3. Conectou...");

        //4. Receber a chave pública
        ObjectInputStream in = new ObjectInputStream(s.getInputStream());
        ObjetoTroca obj = (ObjetoTroca) in.readObject();
        System.out.println("4. Recebeu a chave pública...");

        //5. Criar a chave de sessão
        System.out.println("5. Criando chave de sessão...");
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey keySessao = kgen.generateKey();
        byte[] chaveSessao = keySessao.getEncoded();
        System.out.println("5.1 Criou chave de sessão");

        //5. Criptografar o arquivo com a chave de sessão
        System.out.println("6. Criptograr o arquivo com a chave de sessão...");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySessao);
        System.out.println("6.1 Criou o encriptador de sessão");

        System.out.println("6.2. Iniciando criptografia do arquivo...");
        byte[] b_cripto = cipher.doFinal(barquivo);
        System.out.println("6.3. Criptografou o arquivo.");

        //5. Criptografar arquivo e chave de sessao
        System.out.println("7. Criptografar arquivo e chave de sessão...");
        ObjetoTroca objeto = new ObjetoTroca();
        objeto.setNomeArquivo(chooserArquivo.getSelectedFile().getName());

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, obj.getChavePublica());
        byte[] k_cripto = cipher.doFinal(chaveSessao);
        objeto.setChaveSessao(k_cripto);
        objeto.setArquivo(b_cripto);
        System.out.println("7.1 Criptografou o arquivo e chave de sessão...");

        //6. Enviar o arquivo para Alice
        System.out.println("8. Enviando o arquivo criptografado.");
        System.out.println("8.1. Enviando...");
        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.writeObject(objeto);
        out.close();
        s.close();
        System.out.println("8.2. Envio concluído.");
        System.out.println("9. Fecha conexão...");


        System.exit(0);
    }

}
