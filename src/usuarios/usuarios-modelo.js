const usuariosDao = require('./usuarios-dao');
const { InvalidArgumentError } = require('../erros');
const validacoes = require('../validacoes-comuns');
const bcrypt = require('bcrypt')

class Usuario {
  constructor(usuario) {
    this.id = usuario.id;
    this.nome = usuario.nome;
    this.email = usuario.email;
    this.senhaHash = usuario.senhaHash;

    this.valida();
  }

  async adiciona() {
    if (await Usuario.buscaPorEmail(this.email)) {
      throw new InvalidArgumentError('O usuário já existe!');
    }

    return usuariosDao.adiciona(this);
  }

  async adicionaSenha(senha) {
    validacoes.campoStringNaoNulo(senha, 'senha');
    validacoes.campoTamanhoMinimo(senha, 'senha', 8);
    validacoes.campoTamanhoMaximo(senha, 'senha', 64);

    this.senhaHash = await Usuario.createPasswordHash(senha);
  }

  valida() {
    validacoes.campoStringNaoNulo(this.nome, 'nome');
    validacoes.campoStringNaoNulo(this.email, 'email');
  }


  async deleta() {
    return usuariosDao.deleta(this);
  }

  static async buscaPorId(id) {
    const usuario = await usuariosDao.buscaPorId(id);
    if (!usuario) {
      return null;
    }

    return new Usuario(usuario);
  }

  static async buscaPorEmail(email) {
    const usuario = await usuariosDao.buscaPorEmail(email);
    if (!usuario) {
      return null;
    }

    return new Usuario(usuario);
  }

  static lista() {
    return usuariosDao.lista();
  }

  static createPasswordHash(senha) {
    let costHash = 12
    return bcrypt.hash(senha, costHash)
  }
}

module.exports = Usuario;
