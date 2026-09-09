const Встроенный_модуль_криптографии = require("crypto");

const Символы_кода_числа =
	"АБВГҐДЕЄЁЖЗИІЇЙКЛМНОПРСТУЎФХЦЧШЩ" +
	"ЪЫЬЭЮЯабвгґдеєёжзиіїйклмнопрстуў" +
	"фхцчшщъыьэюяABCDEFGHIJKLMNOPQRST" +
	"UVWXYZabcdefghijklmnopqrstuvwxyz";

class Код {
	static Из_байтов(данные, длина = null) {
		let код = "";
		for (let i = 0; i < данные.length; i += 7) {
			let число = 0n;
			const байтов_в_блоке = Math.min(7, данные.length - i);
			for (let j = 0; j < байтов_в_блоке; j++)
				число += BigInt(данные[i + j]) << BigInt(8 * j);
			const символов = Math.ceil(байтов_в_блоке * 8 / 7);
			for (let j = 0; j < символов; j++) {
				код += Символы_кода_числа[Number(число % 128n)];
				число >>= 7n;
			}
		}
		if (длина !== null && длина > код.length)
			код += Символы_кода_числа[0].repeat(длина - код.length);
		return код;
	}

	static В_байты(код) {
		const байты = [];
		for (let i = 0; i < код.length; i += 8) {
			let число = 0n;
			const символов_в_блоке = Math.min(8, код.length - i);
			for (let j = 0; j < символов_в_блоке; j++) {
				const индекс = Символы_кода_числа.indexOf(код[i + j]);
				if (индекс != -1) число += BigInt(индекс) << BigInt(j * 7);
			}
			const байтов = Math.min(Math.floor(символов_в_блоке * 7 / 8), 7);
			for (let j = 0; j < байтов; j++)
				байты.push(Number((число >> BigInt(8 * j)) & 0xFFn));
		}
		return new Uint8Array(байты);
	}

	static Из_числа(число, длина = null) {
		const байтовая_длина = длина !== null ? длина : Math.ceil(число.toString(2).length / 8);
		const байты = new Uint8Array(байтовая_длина);
		for (let i = 0; i < байтовая_длина; i++)
			байты[i] = Number((число >> BigInt(i * 8)) & 0xFFn);
		return this.Из_байтов(байты, длина);
	}

	static В_число(код) {
		const байты = this.В_байты(код);
		let число = 0n;
		for (let i = 0; i < байты.length; i++)
			число += BigInt(байты[i]) << BigInt(i * 8);
		return Number(число);
	}

	static Числа_в_составной_код(числа, длина) {
		const байты_всех_чисел = [];
		for (const число of числа) {
			const байты_числа = new Uint8Array(длина);
			for (let i = 0; i < длина; i++)
				байты_числа[i] = Number((BigInt(число) >> BigInt(i * 8)) & 0xFFn);
			байты_всех_чисел.push(...байты_числа);
		}
		return this.Из_байтов(байты_всех_чисел);
	}

	static Составной_код_в_числа(код, длина) {
		const байты_всех_чисел = this.В_байты(код);
		const числа = [];
		for (let i = 0; i < байты_всех_чисел.length; i += длина) {
			const байты_числа = байты_всех_чисел.slice(i, i + длина);
			if (байты_числа.length === длина) {
				let число = 0n;
				for (let j = 0; j < байты_числа.length; j++)
					число += BigInt(байты_числа[j]) << BigInt(j * 8);
				числа.push(число);
			}
		}
		return числа;
	}

	static Строку_в_байты(строка) {
		const
			буфер = new ArrayBuffer(строка.length * 2),
			представление = new DataView(буфер);
		for (let сч = 0; сч < строка.length; сч++)
			представление.setUint16(сч * 2, строка.charCodeAt(сч), true);
		return new Uint8Array(буфер);
	}

	static Байты_в_строку(байты) {
		const представление = new DataView(байты.buffer, байты.byteOffset, байты.byteLength);
		let результат = "";
		for (let сч = 0; сч < байты.length; сч += 2)
			результат += String.fromCharCode(представление.getUint16(сч, true));
		return результат;
	}

	static Из_подписи(подпись, длинный_хэш = false) {
		return this.Числа_в_составной_код(подпись, длинный_хэш ? 64 : 32);
	}

	static В_подпись(код, длинный_хэш = false) {
		return this.Составной_код_в_числа(код, длинный_хэш ? 64 : 32);
	}

	static Сгенерировать_синхропосылку() {
		const S = new Uint32Array(2);
		Встроенный_модуль_криптографии.getRandomValues(S);
		return S;
	}

	static Число_в_массив(число, размер_блока = 32, количество_блоков = 8) {
		if (typeof число != "bigint") число = BigInt(число);
		const
			результат =
				new ({ 8: Uint8Array, 32: Uint32Array }[размер_блока] || Array)(количество_блоков),
			маска = (1n << BigInt(размер_блока)) - 1n;
		for (let сч = 0; сч < количество_блоков; сч++) {
			результат[сч] = Number(число & маска);
			число >>= BigInt(размер_блока);
		}
		return результат;
	}
}

module.exports = Код;
