package br.ufsm.politecnico.csi.seguranca.integridade;

import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.*;

/**
 * Created by cpol on 10/04/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * Bob:
 * 1: Selecionar arquivo
 * 2: Ler o arquivo
 * 3: Aplicar Hash no Arquivo
 * 4: Cria par de chaves
 * 5: Criptografa hash com a chave privada
 * 6: Conectar Alice
 * 7: Envia arquivo e chave pública
 * 8: Fecha conexão
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

        //3. Aplicar Hash no Arquivo
        System.out.println("3. Aplicar Hash no Arquivo.");
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hash = md.digest(barquivo);
        System.out.println("3.1 Hash Aplicado.");

        //4. Criar par de chaves
        System.out.println("4. Criar par de chaves...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair kp = keyGen.generateKeyPair();
        System.out.println("4.1 Criou par de chaves");

        //5. Criar emcriptador
        System.out.println("5. Criar criptador...");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPrivate());
        System.out.println("5.1 Criptador criado...");

        //6. Criptografar Hash
        System.out.println("6.2. Iniciando criptografia do Hash...");
        byte[] b_hash = cipher.doFinal(hash);
        System.out.println("6.3. Criptografou o Hash.");

        //7. Conectar à Alice
        Socket s = new Socket("localhost", 3333);
        System.out.println("7. Conectou...");

        //8. Setar Objeto Troca
        System.out.println("8. Setar objeto Troca...");
        ObjetoTroca obj = new ObjetoTroca();
        obj.setNomeArquivo(chooserArquivo.getSelectedFile().getName());
        obj.setChavePublica(kp.getPublic());
        obj.setArquivo(barquivo);
        obj.setAssinatura(b_hash);
        System.out.println("8.1 Setou...");

        //6. Enviar para Alice
        System.out.println("9. Enviando Hash e arquivo para Alice.");
        System.out.println("9.1. Enviando...");
        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.writeObject(obj);
        out.close();
        s.close();
        System.out.println("9.2. Envio concluído.");
        System.out.println("10. Fecha conexão...");

        System.exit(0);
    }

}
