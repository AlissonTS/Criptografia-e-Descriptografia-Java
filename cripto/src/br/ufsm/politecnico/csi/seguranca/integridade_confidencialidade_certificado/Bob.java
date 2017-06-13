package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade_certificado;

import com.sun.org.apache.xml.internal.security.algorithms.MessageDigestAlgorithm;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by cpol on 12/04/2017.
 */
public class Bob {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeySpecException {
        //1. Selecionar o arquivo
        System.out.println("1. Selecionar arquivo.");
        JFileChooser chooserArquivo = new JFileChooser();
        chooserArquivo.setDialogTitle("Selecionar arquivo");
        int escolha = chooserArquivo.showOpenDialog(new JFrame());
        if (escolha != JFileChooser.APPROVE_OPTION) {
            return;
        }
        System.out.println("    1.1. Selecionou arquivo.");

        //2. Ler o arquivo
        File arquivo = new File(chooserArquivo.getSelectedFile().getAbsolutePath());
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] barquivo = new byte[(int) fin.getChannel().size()];
        fin.read(barquivo);
        System.out.println("    1.2. Leu o arquivo.");

        //3. Ler certificado Bob
        File certificadoBob = new File("Alisson (Bob)_cert.xml");
        FileInputStream finBob = new FileInputStream(certificadoBob);
        byte[] b_certificadoBob = new byte[(int) finBob.getChannel().size()];
        finBob.read(b_certificadoBob);
        System.out.println("3. Leu o certificado de Bob.");

        //4. Ler chaves privada bob
        File privadaBob = new File("chavePrivBob.key");
        FileInputStream finChaPrivaBob = new FileInputStream(privadaBob);
        byte[] b_privateBob = new byte[(int) finChaPrivaBob.getChannel().size()];
        finChaPrivaBob.read(b_privateBob);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyBob = kf.generatePrivate(new PKCS8EncodedKeySpec(b_privateBob));
        System.out.println("4. Leu Chave Privada de Bob.");

        //5. Ler chave publica da CA
        File publicaCA = new File("pub.key");
        FileInputStream finChaPubCA = new FileInputStream(publicaCA);
        byte[] b_publicaCA = new byte[(int) finChaPubCA.getChannel().size()];
        finChaPubCA.read(b_publicaCA);
        PublicKey publicKeyCA = kf.generatePublic(new X509EncodedKeySpec(b_publicaCA));
        System.out.println("5. Leu a chave publica do CA.");

        //6. Conectar à Alice
        Socket s = new Socket("localhost", 3333);
        System.out.println("6. Conectou a Alice.");

        //7. Recebe certificado
        ObjectInputStream in = new ObjectInputStream(s.getInputStream());
        ObjetoTroca obj = (ObjetoTroca) in.readObject();
        System.out.println("7. Recebeu certificado.");

        //8. Converter Byte para arquivo xml
        FileOutputStream File = new FileOutputStream("ObjetoCertificadoAlice.xml");
        File.write(obj.getCertificado());
        File.close();
        System.out.println("8. Converteu Arquivo recebido de ALice para XML");

        //9. Lendo certifcado Alice e pegando valores
        FileInputStream fis = new FileInputStream("ObjetoCertificadoAlice.xml");
        BufferedInputStream bis = new BufferedInputStream(fis);
        XMLDecoder xmlDecoder = new XMLDecoder(bis);
        br.ufsm.politecnico.csi.seguranca.pki.Certificado  ObjetoCertificadoAlice = (br.ufsm.politecnico.csi.seguranca.pki.Certificado) xmlDecoder.readObject();
        System.out.println("9. Leu dados do certificado ");

        //10. Verificar validade certificado alice
        SimpleDateFormat SDF = new SimpleDateFormat("dd/MM/yyyy");
        Date dataHoje = new Date();
        System.out.println("10. Verificando data...");

         if(ObjetoCertificadoAlice.getValidoAte().after(dataHoje))
         {
             System.out.println("   10.1. Data do certificado válida");

             //10.1.1 Descriptografar hash da assintura  com chave publica CA
             Cipher cipherHashAssinatura = Cipher.getInstance("RSA");
             cipherHashAssinatura.init(Cipher.DECRYPT_MODE,publicKeyCA);
             byte[] arquivoHashAssinaturaAlice = cipherHashAssinatura.doFinal(ObjetoCertificadoAlice.getAssinatura());
             System.out.println("   10.1.1. Descriptografou a Assinatura(Hash) de Alice.");
             /*
             Assinatura Certificado  = nome.getNome().getBytes("ISO-8859-1")
                     +"30/06/2017".getBytes("ISO-8859-1")
                     +publicKeyCA;
            */

             // Criando hash com nome data validadee chave publica.
             MessageDigest md = MessageDigest.getInstance("SHA-256");
             ByteArrayOutputStream bout = new ByteArrayOutputStream();
             bout.write(ObjetoCertificadoAlice.getNome().getBytes("ISO-8859-1"));
             bout.write("30/06/2017".getBytes("ISO-8859-1"));
             bout.write(ObjetoCertificadoAlice.getChavePublica());
             byte [] hash = md.digest(bout.toByteArray());
             System.out.println("   10.1.2. Criou Hash concatenado.");

             System.out.println("   10.1.3. Compara Hashs.");
             if(!Arrays.equals(hash,arquivoHashAssinaturaAlice))
             {
                 System.out.println("   10.1.3.1 Assinatura Inválida");
                 System.exit(0);
             }
             System.out.println("   10.1.3.1. Assinatura Válida");

             //10.1.3.1. Cria chave de sessão para arquivo
             KeyGenerator kgen = KeyGenerator.getInstance("AES");
             kgen.init(128);
             SecretKey aeskey_sessao = kgen.generateKey();
             byte[] chave_sessao_Bob = aeskey_sessao.getEncoded();
             System.out.println("   10.1.3.2. Criou a Chave de sessão.");

             //10.1.3.1. Criar o encriptador e criptografar arquivo com chave de sessão
             Cipher cipher_arquivo = Cipher.getInstance("AES");
             cipher_arquivo.init(Cipher.ENCRYPT_MODE, aeskey_sessao);
             byte[] arquivo_cripto_Bob = cipher_arquivo.doFinal(barquivo);
             System.out.println("   10.1.3.3. Criptografou o arquivo.");

             //9. Criar encriptador e criptografar chave sessao com ch publica Alice que esta no certificado
             PublicKey publicKeyAlice = kf.generatePublic(new X509EncodedKeySpec(ObjetoCertificadoAlice.getChavePublica()));
             Cipher cipher_sessao = Cipher.getInstance("RSA");
             cipher_sessao.init(Cipher.ENCRYPT_MODE,publicKeyAlice);
             byte[] chave_sessao_cripto_Bob = cipher_sessao.doFinal(chave_sessao_Bob);
             System.out.println("   10.1.3.4. Criptografou chave de sessão do Bob.");

             //9. Criar hash do Arquivo a ser enviado para alice
             md = MessageDigest.getInstance("SHA-256");
             byte[] arquivoHash = md.digest(barquivo);
             System.out.println("   10.1.3.5. Gerou Hash do Arquivo criado.");

             //9. Criar o encriptador e criptografar arquivo hash com a chave privada de Bob
             Cipher cipher_hash = Cipher.getInstance("RSA");
             cipher_hash.init(Cipher.ENCRYPT_MODE,privateKeyBob );
             byte[] hash_cripto_bob = cipher_hash.doFinal(arquivoHash);
             System.out.println("   10.1.3.6. Criptografou hash de Bob");

             //inicia novamente conexão
             s.close();
             s = new Socket("localhost", 3333);

             //10. Envia para Alice(Arquivo,ch sessão,hash(TodosCripto)e chave publica
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
             ObjetoTroca objEnvio = new ObjetoTroca();
             objEnvio.setChaveSessao(chave_sessao_cripto_Bob);
             objEnvio.setArquivo(arquivo_cripto_Bob);
             objEnvio.setNomeArquivo(chooserArquivo.getSelectedFile().getName());
             objEnvio.setAssinatura(hash_cripto_bob);
             objEnvio.setCertificado(b_certificadoBob);
             out.writeObject(objEnvio);
             out.close();
             System.out.println("   10.1.3.7. Dados enviados");

         }else if(ObjetoCertificadoAlice.getValidoAte().after(dataHoje))
         {
             System.out.println("   10.2 Data do certificado vencida");
             s.close();
             System.exit(0);
         }

        //8.1.5.6. Fechar conexão
        System.out.println("11. Conexão fechada.");
        s.close();

    }
}
