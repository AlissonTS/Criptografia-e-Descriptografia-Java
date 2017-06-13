package br.ufsm.politecnico.csi.seguranca.integridade_confidencialidade;

import java.io.Serializable;
import java.security.PublicKey;

/**
 * Created by Alisson on 14/04/2017.
 */
public class ObjetoTroca implements Serializable {

    private byte[] arquivo;
    private String nomeArquivo;
    private byte[] chaveSessao;
    private byte[] assinatura;
    private PublicKey chavePublica;

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

    public byte[] getChaveSessao() {
        return chaveSessao;
    }

    public void setChaveSessao(byte[] chaveSessao) {
        this.chaveSessao = chaveSessao;
    }

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
}
