package br.ufsm.politecnico.csi.seguranca.confidencialidade;

import java.io.Serializable;
import java.security.PublicKey;

/**
 * Created by cpol on 29/03/2017.
 */
public class ObjetoTroca implements Serializable {

    private byte[] arquivo;
    private String nomeArquivo;
    private PublicKey chavePublica;
    private byte[] chaveSessao;

    public byte[] getChaveSessao() {
        return chaveSessao;
    }

    public void setChaveSessao(byte[] chaveSessao) {
        this.chaveSessao = chaveSessao;
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
