package br.ufsm.politecnico.csi.seguranca;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

/**
 * Created by cpol on 22/03/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 */
public class CriptografaArquivo{

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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
        System.out.println("2. Leu o arquivo.");

        //3. Criar a chave
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey aesKey = kgen.generateKey();
        byte[] chave = aesKey.getEncoded();
        System.out.println("3. Criou a chave.");

        //4. Criar o encriptador
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        System.out.println("4. Criou o encriptador.");

        //5. Criptografar
        System.out.println("5. Iniciando criptografia...");
        byte[] b_cripto = cipher.doFinal(barquivo);
        System.out.println("5. Criptografou.");

        //6. Escrever o arquivo
        System.out.println("6. Escrevendo o arquivo criptografado.");
        File saida = new File(chooserArquivo.getSelectedFile().getAbsolutePath()
                + ".cripto");
        OutputStream fout = new FileOutputStream(saida);
        fout.write(b_cripto);
        fout.close();

        //7. Salvar a chave
        System.out.println("7. Salvando a chave");
        File fchave = new File(chooserArquivo.getSelectedFile().getAbsolutePath()
                + ".key");
        OutputStream outChave = new FileOutputStream(fchave);
        outChave.write(chave);
        outChave.close();

        System.exit(0);
    }

}
