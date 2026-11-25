/* Criptografia do VaultKey usando a Web Crypto API do navegador.
   - A senha mestra nunca é salva.
   - Dela derivamos uma chave AES de 256 bits com PBKDF2 (SHA-256, 310.000 iterações) e um "sal" aleatório.
   - O cofre inteiro é cifrado com AES-GCM, que também detecta qualquer alteração nos dados. */

const Cripto = (() => {
  const ITERACOES = 310000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const paraB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const deB64 = (txt) => Uint8Array.from(atob(txt), (c) => c.charCodeAt(0));

  async function derivarChave(senha, sal) {
    const base = await crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: sal, iterations: ITERACOES, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function cifrar(chave, objeto) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const dados = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, chave, enc.encode(JSON.stringify(objeto)));
    return { iv: paraB64(iv), dados: paraB64(dados) };
  }

  async function decifrar(chave, pacote) {
    const texto = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: deB64(pacote.iv) }, chave, deB64(pacote.dados));
    return JSON.parse(dec.decode(texto));
  }

  const novoSal = () => paraB64(crypto.getRandomValues(new Uint8Array(16)));

  return { derivarChave, cifrar, decifrar, novoSal, deB64 };
})();
