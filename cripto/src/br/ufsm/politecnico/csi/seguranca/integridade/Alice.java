package br.ufsm.politecnico.csi.seguranca.integridade;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by cpol on 10/04/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * * Alice
 * 1: Abrir ServerSocket();
 * 2. Aguardar conexão
 * 3: Recebe chave publica
 * 4: Recebe resumo
 * 5: Recebe arquivo
 * 6: Aplicar hash arquivo recebido
 * 7: Decifrar resumo ch publica Bob
 * 8: Comparar resumos
 * 9: Fecha conexão
 * 10: Se verdadeiro grava no disco
 */
public class Alice {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        //1. Abrir Server Socket
        System.out.println("1. Abrir ServerSocket...");
        ServerSocket ss = new ServerSocket(3333);

        while (true) {
            //2. Aguardar Conexão
            System.out.println("2. Aguardando conexões na porta 3333...");
            Socket s = ss.accept();
            System.out.println("2.1. Cliente conectado.");

            //3. Receber Objeto Troca
            System.out.println("3. Receber Objeto Troca...");
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            ObjetoTroca obj = (ObjetoTroca) in.readObject();
            System.out.println("3.1 Recebeu Objeto Troca...");

            //4. Aplicar Hash no Arquivo do Objeto Troca
            System.out.println("4. Aplicar Hash no Arquivo.");
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance("SHA-1");
            }
            catch(NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            byte[] hash_arquivo = md.digest(obj.getArquivo());
            System.out.println("4.1 Hash Aplicado.");

            //5. Criar o desencriptador
            System.out.println("5. Criar desencriptador...");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, obj.getChavePublica());
            System.out.println("5.1 Criou o desencriptador da chave pública.");

            //5. Descriptografar hash
            System.out.println("7. Iniciando descriptografia do hash...");
            byte[] hash_assinatura = cipher.doFinal(obj.getAssinatura());
            System.out.println("7.1 Descriptografou hash.");

            // Comparar os dois hash
            if(Arrays.equals(hash_arquivo, hash_assinatura)){
                //6. Se verdadeiro, escrever o arquivo no disco
                System.out.println("8. Escrevendo o arquivo.");
                File saida = new File(obj.getNomeArquivo());
                OutputStream fout = new FileOutputStream(saida);
                fout.write(obj.getArquivo());
                fout.close();
                s.close();
                System.out.println("8.1. Concluído, arquivo salvo..\n");
            }else{
                System.out.println("8.1. Erro! Assinatura inválida.");
            }

        }
    }
}
