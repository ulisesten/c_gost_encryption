/**
 * Encryption and decryption function only
 */
 

const gost = require("gost-cryptography");
const settings = require("./configuration");
const { d, Q } = gost.ЭЦП.Сгенерировать_ключи();

class EncryptService {
  SECRET = settings.getSecretKey();
  x_vector = settings.getXVector();

  
  /**
   * @param data string
   * @returns string firma **/
  sign(data) {
    ///    gost.EDS.firmar
    return gost.ЭЦП.Подписать(data, d);
  }


  /**
   * @param data string datos sin cifrar
   * @param signature string datos cifrados
   * @returns bool **/
  verify(data, signature) {
    ///     gost.EDS.comprobar
    return gost.ЭЦП.Проверить(data, signature, Q);
  }


  /**
   * @brief Encripta con posibilidad de revertir
   * @param data any
   * @returns string retorna un string encriptado que es reversible **/
  reversible_encrypt(data) {
    if(typeof data === 'object' && data !== null) {
      data = JSON.stringify(data);
    }

    const input = gost.Код.Строку_в_байты(data)

    ///    gost.encriptacion.proceso_con_reversion
    const token = gost.Шифрование.Гаммование_с_обратной_связью(
      input,
      this.x_vector,
      this.SECRET,
      null,
      false,
    );

    const b64_token = (Buffer.from(token)).toString('base64');

    return b64_token;
  }


  /**
   * @param texto_cifrado string
   * @returns string texto descifrado **/
  decrypt(texto_cifrado) {
    const jsonString = Buffer.from(texto_cifrado, 'base64');
    
    ///    gost.encriptacion.proceso_con_reversion
    const decryptedResult = gost.Шифрование.Гаммование_с_обратной_связью(
      jsonString,
      this.x_vector,
      this.SECRET,
      null,
      true,
    );

    return gost.Код.Байты_в_строку(decryptedResult);
  }


  /**
   * @param data string, contraseña a encryptar
   * @returns string **/
  hash(data) {
    ///    gost.hash.calcular
    const input = gost.Код.Строку_в_байты(data);
    return gost.Хэшевание.Вычислить(input, false).toString(16);
  }
  
}


module.exports = new EncryptService();
