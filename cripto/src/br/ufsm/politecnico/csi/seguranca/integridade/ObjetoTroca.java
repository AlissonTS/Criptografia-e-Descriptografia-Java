package br.ufsm.politecnico.csi.seguranca.integridade;

import java.security.PublicKey;
import java.io.Serializable;

/**
 * Created by cpol on 10/04/2017.
 */public class ObjetoTroca implements Serializable {


    private byte[] arquivo;
    private String nomeArquivo;
    private PublicKey chavePublica;
    private byte[] assinatura;

    public byte[] getAssinatura() {
        return assinatura;
    }

    public void setAssinatura(byte[] assinatura) {
        this.assinatura = assinatura;
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }

    public void setChavePublica(PublicKey chavePublica) {
        this.chavePublica = chavePublica;
    }

    public byte[] getArquivo() {
        return arquivo;
    }

    public void setArquivo(byte[] arquivo) {
        this.arquivo = arquivo;
    }

    public String getNomeArquivo() {
        return nomeArquivo;
    }

    public void setNomeArquivo(String nomeArquivo) {
        this.nomeArquivo = nomeArquivo;
    }
}
