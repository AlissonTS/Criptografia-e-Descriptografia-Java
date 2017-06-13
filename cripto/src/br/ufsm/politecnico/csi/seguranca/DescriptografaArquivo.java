package br.ufsm.politecnico.csi.seguranca;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

/**
 * Created by cpol on 27/03/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 */
public class DescriptografaArquivo {

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
        byte[] bcripto = new byte[(int) fin.getChannel().size()];
        fin.read(bcripto);
        System.out.println("2. Leu o arquivo.");

        System.out.println("3. Lendo a chave.");
        FileInputStream inChave = new FileInputStream(
                chooserArquivo.getSelectedFile().getAbsolutePath().replaceAll(".cripto", ".key"));
        byte[] bchave = new byte[(int) inChave.getChannel().size()];
        inChave.read(bchave);
        SecretKeySpec ks = new SecretKeySpec(bchave, "AES");

        //4. Criar o desencriptador
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, ks);
        System.out.println("4. Criou o encriptador.");

        //5. Criptografar
        System.out.println("5. Iniciando criptografia...");
        byte[] b_arquivo = cipher.doFinal(bcripto);
        System.out.println("5. Criptografou.");

        //6. Escrever o arquivo
        System.out.println("6. Escrevendo o arquivo criptografado.");
        File saida = new File(chooserArquivo.getSelectedFile().getAbsolutePath().replaceAll(".cripto", "") + ".new");
        OutputStream fout = new FileOutputStream(saida);
        fout.write(b_arquivo);
        fout.close();
        System.out.println("\n\nConcluído.");

        System.exit(0);
    }

}
