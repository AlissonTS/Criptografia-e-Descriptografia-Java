package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade_certificado;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.ServerSocket;
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
public class Alice {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeySpecException {


        //1. Abrindo Socket
        ServerSocket ss = new ServerSocket(3333);
        System.out.println("1. Socket aberto");

        //2. Ler o certificado
        File arquivo = new File("Alisson (Alice)_cert.xml");
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] B_XML = new byte[(int) fin.getChannel().size()];
        fin.read(B_XML);
        System.out.println("2. Leu o Certificado.");

        //3. Aguarda Conexão
        while (true) {
            System.out.println("3. Aguardando conexões...");
            Socket s = ss.accept();
            System.out.println("    3.1 Cliente conectado.");

            //4. Estanciar XML
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            ObjetoTroca certificado = new ObjetoTroca();
            certificado.setCertificado(B_XML);
            out.writeObject(certificado);
            out.close();
            System.out.println("4. Enviou o certificado.");

            ///////////////////////////////////////////////////////////////////////////////////////
            s.close();
            s = ss.accept();

            //5. Recebe dados de Bob
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            ObjetoTroca objetoBob = (ObjetoTroca) in.readObject();
            System.out.println("5. Dados recebidos.");

            //6. Converter Byte para arquivo xml
            FileOutputStream File = new FileOutputStream("ObjetoCertificadoBob.xml");
            File.write(objetoBob.getCertificado());
            File.close();
            System.out.println("6. Converteu Arquivo recebido de Bob para XML");

            //7. Lendo certifcado Bob e pegando valores
            FileInputStream fis = new FileInputStream("ObjetoCertificadoBob.xml");
            BufferedInputStream bis = new BufferedInputStream(fis);
            XMLDecoder xmlDecoder = new XMLDecoder(bis);
            br.ufsm.politecnico.csi.seguranca.pki.Certificado  ObjetoCertificadoBob = (br.ufsm.politecnico.csi.seguranca.pki.Certificado) xmlDecoder.readObject();
            System.out.println("7. Leu dados do certificado ");

            //8. Verificar validade certificado alice
            SimpleDateFormat SDF = new SimpleDateFormat("dd/MM/yyyy");
            Date dataHoje = new Date();
            System.out.println("8. Verificando data...");


            if(!ObjetoCertificadoBob.getValidoAte().after(dataHoje)) {
                System.out.println("    8.1 Certificado vencido");
                s.close();
                System.exit(0);

            }
            System.out.println("   8.1. Data do certificado válida");

            //9. Ler chave publica da CA
            File publicaCA = new File("pub.key");
            FileInputStream finChaPubCA = new FileInputStream(publicaCA);
            byte[] b_publicaCA = new byte[(int) finChaPubCA.getChannel().size()];
            finChaPubCA.read(b_publicaCA);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKeyCA = kf.generatePublic(new X509EncodedKeySpec(b_publicaCA));
            System.out.println("    8.1.1 Leu a chave publica do CA.");

            //8.1.2Descriptografar hash da assintura  com chave publica CA
            Cipher cipherHashAssinatura = Cipher.getInstance("RSA");
            cipherHashAssinatura.init(Cipher.DECRYPT_MODE,publicKeyCA);
            byte[] arquivoHashAssinaturaBob = cipherHashAssinatura.doFinal(ObjetoCertificadoBob.getAssinatura());
            System.out.println("   8.1.2. Descriptografou a Assinatura(Hash) de Bob.");

            //8.1.3 Criando hash com nome data validadee chave publica.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(ObjetoCertificadoBob.getNome().getBytes("ISO-8859-1"));
            bout.write("30/06/2017".getBytes("ISO-8859-1"));
            bout.write(ObjetoCertificadoBob.getChavePublica());
            byte [] hash = md.digest(bout.toByteArray());
            System.out.println("   8.1.4. Criou Hash concatenado.");

            System.out.println("   8.1.5. Compara Hashs.");
            if(!Arrays.equals(hash,arquivoHashAssinaturaBob))
            {
                System.out.println("   8.1.5.1 Assinatura Inválida");
                System.exit(0);
            }
            System.out.println("   8.1.5.1. Assinatura Válida");

            //8.1.5.1. ler chave privada de alice
            File privadaAlice = new File("chavePrivAlice.key");
            FileInputStream finChaPrivaAlice = new FileInputStream(privadaAlice);
            byte[] b_privateAlice = new byte[(int) finChaPrivaAlice.getChannel().size()];
            finChaPrivaAlice.read(b_privateAlice);
            kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKeyAlice = kf.generatePrivate(new PKCS8EncodedKeySpec(b_privateAlice));
            System.out.println("    8.1.5.1. Leu Chave Privada de Alice.");

            //8.1.5.2. .Desifrar chave da sessao usando chave privada alice
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKeyAlice);
            byte[] c_sessao= cipher.doFinal(objetoBob.getChaveSessao());
            SecretKeySpec ks = new SecretKeySpec(c_sessao,"AES");
            System.out.println("    8.1.5.2. Descriptografou chave de sessão.");

            //8.1.5.3 Descriptografar arquivo com chave de sessão do Alice
            Cipher cipher_arquivo = Cipher.getInstance("AES");
            cipher_arquivo.init(Cipher.DECRYPT_MODE,ks);
            byte[] b_arquivo = cipher_arquivo.doFinal(objetoBob.getArquivo());
            System.out.println("    8.1.5.3. Descriptografou o arquivo.");

            //8.1.5.4. Criar hash do Arquivo recebido de Bob
            md = MessageDigest.getInstance("SHA-256");
            byte[] arquivoHash = md.digest(b_arquivo);
            System.out.println("    8.1.5.4. Hash do Arquivo criado.");

            //8.1.5.5. Descriptografar hash com chave publica Bob
            PublicKey publicKeyBob = kf.generatePublic(new X509EncodedKeySpec(ObjetoCertificadoBob.getChavePublica()));
            Cipher cipherHASH = Cipher.getInstance("RSA");
            cipherHASH.init(Cipher.DECRYPT_MODE,publicKeyBob);
            byte[] arquivoHashBob = cipherHASH.doFinal(objetoBob.getAssinatura());
            System.out.println("    8.1.5.5. Descriptografou a Assinatura(Hash).");

            System.out.println("    8.1.5.6. Compara os hashs");
            if(Arrays.equals(arquivoHash,arquivoHashBob))
            {
                System.out.println("    8.1.5.6.1. Hashs Iguais.");
                //11. Escrever o arquivo
                File saida = new File(objetoBob.getNomeArquivo());
                OutputStream fout = new FileOutputStream(saida);
                fout.write(b_arquivo);
                fout.close();
                System.out.println("    8.1.5.6.2. Arquivo gravado");
            }
            else {
                System.out.println("    8.1.5.6. ERRO! Hashs Invalida.");

            }
            //8.1.5.6. Fechar conexão
            System.out.println("    8.1.5.7. Conexão fechada.\n");
            s.close();




        }
    }
}
