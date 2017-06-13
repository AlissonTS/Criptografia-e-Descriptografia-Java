package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by Alisson on 14/04/2017.
 * ALISSON TRINDADE SOUZA - 201321762
 *
 * * Alice
 * 1. Abrir o server Socket
 * 2. Gerar par de chaves
 * 3. Aguardar conexão
 * 4. Enviar chave pública
 * 5. Receber dados de Bob
 * 6. Descriptografar hash com chave pública do Bob
 * 7. Descriptografar chave de sessão do Bob com chave privada da Alice
 * 8. Descriptografar arquivo com chave de sessão do Bob
 * 9. Criar hash com o arquivo descriptografado recebido de Bob
 * 10. Comparar hash
 * 11. Se verdadeiro deve-se gravar no disco
 */
public class Alice {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        //1. Abrir Server Socket
        System.out.println("1. Abrir ServerSocket...");
        ServerSocket ss = new ServerSocket(3333);

        //2. Gerar Par de Chaves
        System.out.println("2. Gerar par de chaves...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair kp = keyGen.generateKeyPair();
        System.out.println("2.1 Gerou par de chaves");

        while (true) {
            //3. Aguardar Conexão
            System.out.println("3. Aguardando conexões na porta 3333...");
            Socket s = ss.accept();
            System.out.println("3.1. Cliente conectado.");

            //4. Enviar a chave pública
            System.out.println("4. Enviando chave Pública...");
            ObjetoTroca obj = new ObjetoTroca();
            obj.setChavePublica(kp.getPublic());
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            out.writeObject(obj);
            out.flush();
            System.out.println("4.1 Chave pública enviada...");

            //5. Lendo dados do do socket - Receber dados do Bob
            System.out.println("5. Lendo o socket...");
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            ObjetoTroca objetoTroca = (ObjetoTroca) in.readObject();
            System.out.println("5.1 Leu e recebeu dados no socket.");

            //6. Criar o descriptador e descriptografar hash com chave Pública de Bob
            System.out.println("6. Criar descriptador...");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, objetoTroca.getChavePublica());
            System.out.println("6.1 Criou o desencriptador com chave pública recebida.");

            System.out.println("6.2. Iniciando descriptografia do hash...");
            byte[] hash_assinatura = cipher.doFinal(objetoTroca.getAssinatura());
            System.out.println("6.3 Descriptografou o hash.");

            //7. Criar o descriptador com chave privada de Alice e descriptografar chave de sessão de Bob
            System.out.println("7. Criar descriptador...");
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            System.out.println("7.1 Criou o desencriptador com chave pública recebida.");

            System.out.println("7.2. Iniciando descriptografia da chave de sessão...");
            byte[] kSessao = cipher.doFinal(objetoTroca.getChaveSessao());
            System.out.println("7.3 Descriptografou a chave de sessão.");

            //8. Criar descriptador e descriptografar arquivo com a chave de sessão
            System.out.println("8. Criação da SecretKey com a chave de sessão...");
            cipher = Cipher.getInstance("AES");
            SecretKey k_sessao = new SecretKeySpec(kSessao, 0, kSessao.length, "AES");
            System.out.println("8.1 Chave criada com sucesso.");

            System.out.println("8.2 Descriptografar arquivo.");
            cipher.init(Cipher.DECRYPT_MODE, k_sessao);
            byte[] b_arquivo = cipher.doFinal(objetoTroca.getArquivo());
            System.out.println("8.3 Arquivo descriptografado.");

            //9. Aplicar Hash no Arquivo descriptografado
            System.out.println("9. Aplicar Hash no Arquivo descriptografado.");
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance("SHA-1");
            }
            catch(NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            byte[] hash_arquivo = md.digest(b_arquivo);
            System.out.println("9.1 Hash Aplicado.");

            //10. Comparar as duas assinaturas (hashs)
            System.out.println("10. Comparar as duas assinaturas.");
            if(Arrays.equals(hash_arquivo, hash_assinatura)){
                //Se verdadeiro, escrever o arquivo no disco
                System.out.println("10.1 Assinaturas compatíveis. Escrevendo o arquivo no disco.");
                File saida = new File(objetoTroca.getNomeArquivo());
                OutputStream fout = new FileOutputStream(saida);
                fout.write(objetoTroca.getArquivo());
                fout.close();
                s.close();
                System.out.println("10.2. Concluído, arquivo salvo..\n");
            }else{
                System.out.println("10.1. Erro! Assinatura inválida.");
            }
        }
    }
}
