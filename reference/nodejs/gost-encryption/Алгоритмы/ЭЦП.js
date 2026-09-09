/**
*
*  Электронная цифровая подпись по алгоритму ГОСТ Р 34.10-2012.
*
**/

class ГОСТ_ЭЦП {

	static #Хэшевание;
	static #Случайные_байты;

	static Установить_источник_случайности(функция) {
		this.#Случайные_байты = функция;
	}

	static Установить_модуль_хэшевания(модуль) {
		this.#Хэшевание = модуль;
	}

	static #Длина_числа(число) {
		let длина = 0;
		while (число > 0n) {
			число >>= 1n;
			длина++;
		}
		return длина;
	}

	static #Случайное_число(длина) {
		const массив = this.#Случайные_байты(Math.ceil(длина / 8));
		if ((длина & 7) != 0)
			массив[массив.length - 1] &= (1 << (длина & 7)) - 1;
		let число = 0n;
		for (let сч = 0n; сч < массив.length; сч++)
			число += BigInt(массив[сч]) << 8n * сч;
		return число;
	}

	static #НОД(a, b, к) {
		if (a == 0n) {
			к.x = 0n, к.y = 1n;
			return b;
		}
		const
			к_ = { x: 0n, y: 0n },
			результат = this.#НОД(b % a, a, к_);
		к.x = к_.y - (b / a) * к_.x;
		к.y = к_.x;
		return результат;
	}

	static #Обратное_по_модулю(a, m) {
		const к = { x: 0n, y: 0n };
		if (this.#НОД(a, m, к) != 1n)
			return null;
		else
			return (к.x % m + m) % m;
	}

	static #В_степень_по_модулю(b, e, n) {
		if (n == 0n) return null;
		else if (n == 1n) return 0n;
		b %= n;
		let r = 1n;
		while (e > 0) {
			if ((e & 1n) == 1n)
				r = (r * b) % n;
			e >>= 1n;
			b = b ** 2n % n;
		}
		return r
	}

	static #Сложить_точки_ЭК(x1, y1, x2, y2, a, b, p) {
		let dx, dy;

		if (x1 == x2 && y1 == y2) {
			dy = 3n * x1 ** 2n + a;
			dx = 2n * y1;
		}
		else if (x1 == x2 && y1 == p - y2 % p) {
			return [0n, 0n];
		}
		else {
			dy = y2 > y1 ? y2 - y1 : p - (y1 - y2);
			dx = x2 > x1 ? x2 - x1 : p - (x1 - x2);
		}

		let обратное = this.#Обратное_по_модулю(dx, p);
		if (обратное === null)
			обратное = 0n;
		const
			лямбда = (dy * обратное) % p,
			квадрат = лямбда ** 2n;

		let x3, y3;

		if (квадрат > x1) {
			const разница = квадрат - x1;
			x3 = разница > x2 ? (разница - x2) % p : p - (разница + x2) % p;
		}
		else
			x3 = p - (x1 - квадрат + x2) % p;

		if (x1 > x3) {
			const произведение = лямбда * (x1 - x3);
			y3 = произведение > y1 ? (произведение - y1) % p : p - (произведение + y1) % p;
		}
		else
			y3 = p - (лямбда * (x3 - x1) + y1) % p;

		return [x3, y3];
	}

	static #Умножить_точку_ЭК(x, y, a, b, p, множитель) {
		let x_ = x, y_ = y, сумма;
		множитель--;
		while (множитель != 0n) {
			if ((множитель & 1n) != 0n) {
				сумма = this.#Сложить_точки_ЭК(x_, y_, x, y, a, b, p);
				x_ = сумма[0]; y_ = сумма[1];
			}
			сумма = this.#Сложить_точки_ЭК(x, y, x, y, a, b, p);
			x = сумма[0]; y = сумма[1];
			множитель >>= 1n;
		}
		return [x_, y_];
	}

	static Подписать(
		h, d,
		{P, a, b, p, q, длинный_хэш} = this.Наборы_параметров[this.#Параметры_по_умолчанию]
	) {
		if (typeof h != "bigint")
			h = this.#Хэшевание.Вычислить(h, длинный_хэш);
		let e = h % q;
		if (e == 0n) e = 1n;
		let r, s;
		do {
			let k;
			do k = this.#Случайное_число(this.#Длина_числа(q));
			while (k == 0 || k >= q);
			const C = this.#Умножить_точку_ЭК(P[0], P[1], a, b, p, k);
			r = C[0] % q;
			s = (r * d + k * e) % q;
		} while (s == 0n || r == 0n);
		return [r, s];
	}

	static Проверить(
		h, подпись, Q,
		{P, a, b, p, q, длинный_хэш} = this.Наборы_параметров[this.#Параметры_по_умолчанию]
	) {
		if (typeof h != "bigint")
			h = this.#Хэшевание.Вычислить(h, длинный_хэш);
		let r, s;
		[r, s] = подпись;
		if (r == 0n || s == 0n || q <= r || q <= s)
			return false;
		let e = h % q;
		if (e == 0n) e = 1n;
		let v = this.#Обратное_по_модулю(e, q);
		if (v === null) v = 0n;
		const
			пр1 = this.#Умножить_точку_ЭК(P[0], P[1], a, b, p, (s * v) % q),
			пр2 = this.#Умножить_точку_ЭК(Q[0], Q[1], a, b, p, q - (r * v) % q),
			C = this.#Сложить_точки_ЭК(пр1[0], пр1[1], пр2[0], пр2[1], a, b, p),
			R = C[0] % q;
		return R == r;
	}

	static Сгенерировать_ключи(
		{P, a, b, p, q, длинный_хэш} = this.Наборы_параметров[this.#Параметры_по_умолчанию],
		строчное_представление = true
	) {
		let d;
		do d = this.#Случайное_число(this.#Длина_числа(q));
		while (q <= d || d == 0n);
		const Q = this.#Умножить_точку_ЭК(P[0], P[1], a, b, p, d);
		return { d, Q };
	}

	static #Тест_на_простоту(число, ф_случ, повторений) {
		const Разложить = s => {
			let t = 0;
			while ((s & 1n) == 0n) s >>= 1n, t++;
			return [s, t];
		};
		if (число == 2n || число == 3n) return true;
		else if (число < 2n || (число & 1n) == 0n) return false;
		else {
			let t, s;
			[t, s] = Разложить(число - 1n);
			for (let i = 0; i < повторений; i++) {
				let x = this.#В_степень_по_модулю(ф_случ(), t, число);
				if (x == 1n || x == число - 1n) continue;
				for (let j = 0; j < s - 1; j++) {
					x = this.#В_степень_по_модулю(x, 2n, число);
					if (x == 1n) return false;
					else if (x == число - 1n) break;
				}
				if (x != число - 1n) return false;
			}
			return true;
		}
	}

	static Проверить_параметры({d, Q}, {P, a, b, p, q, длинный_хэш}) {
		const [Q_x, Q_y] = Q, [P_x, P_y] = P;
		const результат = [];
		const длина_хэша = длинный_хэш ? 512 : 256;
		const m = q;
		if (4n > p) результат.push("Слишком малое число p.");
		if (p <= a || p <= b) результат.push("Число a или b не принадлежит F_p.");
		const a_3_4 = 4n * a ** 3n, b_2_27 = 27n * b ** 2n;
		if ((a_3_4 + b_2_27) % p == 0) результат.push("4a^3+27b^2 сравнимо по модулю p с нулём.");
		const дл_q = this.#Длина_числа(q);
		if (дл_q < длина_хэша - (длина_хэша >>> 7) || дл_q > длина_хэша) результат.push("Число q неверной длины.");
		if (P_x == 0n && P_y == 0n) результат.push("P равно O.");
		const qP = this.#Умножить_точку_ЭК(P_x, P_y, a, b, p, q);
		if (qP[0] != 0n || qP[1] != 0n) результат.push("qP не равно O.");
		const dP = this.#Умножить_точку_ЭК(P_x, P_y, a, b, p, d);
		if (dP[0] != Q_x || dP[1] != Q_y) результат.push("Q не равно dP.");
		if (q <= d || d == 0n) результат.push("Число d неверной длины.");
		const B = длина_хэша == 256 ? 31 : 131;
		let равно_1 = false;
		for (let t = 1; t <= B; t++)
			if (this.#В_степень_по_модулю(p, BigInt(t), q) == 1) {
				равно_1 = true; break;
			}
		if (равно_1) результат.push("P^t (mod q) равно 1.");
		if (m % q != 0n) результат.push("n не принадлежит Z."); 
		if (m == p) результат.push("m равно p.");
		let обратное = this.#Обратное_по_модулю(a_3_4 + b_2_27, p);
		if (обратное === null) обратное = 0n;
		const J_E = (1728n * a_3_4 * обратное) % p;
		if (J_E == 0n || J_E == 1728n) результат.push("J_E равно 0 или 1728.");
		if ((P_y * P_y) % p != (P_x ** 3n + a * P_x + b) % p) результат.push("P_y не соответствует P_x.");
		if ((Q_y * Q_y) % p != (Q_x ** 3n + a * Q_x + b) % p) результат.push("Q_y не соответствует Q_x.");
		const дл_p = this.#Длина_числа(p);
		if (!this.#Тест_на_простоту(p, () => {
			let сл_ч;
			do сл_ч = this.#Случайное_число(дл_p); while (!(сл_ч > 1 && сл_ч < p));
			return сл_ч;
		}, 50)) результат.push("p не простое число.");
		if (!this.#Тест_на_простоту(q, () => {
			let сл_ч;
			do сл_ч = this.#Случайное_число(дл_q); while (!(сл_ч > 1 && сл_ч < q));
			return сл_ч;
		}, 50)) результат.push("q не простое число.");
		return результат.join(" ");
	}

	static #Параметры_по_умолчанию = 4;

	static Наборы_параметров = [
		{ // [0] GostR3410-2001-ParamSet-CC
			p: 0xC0000000000000000000000000000000000000000000000000000000000003C7n,
			q: 0x5FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF606117A2F4BDE428B7458A54B6E87B85n,
			a: 0xC0000000000000000000000000000000000000000000000000000000000003C4n,
			b: 0x2D06B4265EBC749FF7D0F1F1F88232E81632E9088FD44B7787D5E407E955080Cn,
			P: [
				0x0000000000000000000000000000000000000000000000000000000000000002n,
				0xA20E034BF8813EF5C18D01105E726A17EB248B264AE9706F440BEDC8CCB6B22Cn
			],
			длинный_хэш: false
		},
		{ // [1] GostR3410-2001-TestParamSet
			p: 0x8000000000000000000000000000000000000000000000000000000000000431n,
			q: 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3n,
			a: 0x0000000000000000000000000000000000000000000000000000000000000007n,
			b: 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7En,
			P: [
				0x0000000000000000000000000000000000000000000000000000000000000002n,
				0x08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8n
			],
			длинный_хэш: false
		},
		{ // [2] GostR3410-2001-CryptoPro-A-ParamSet
			p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97n,
			q: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893n,
			a: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94n,
			b: 0x00000000000000000000000000000000000000000000000000000000000000A6n,
			P: [
				0x0000000000000000000000000000000000000000000000000000000000000001n,
				0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14n
			],
			длинный_хэш: false
		},
		{ // [3] GostR3410-2001-CryptoPro-B-ParamSet
			p: 0x8000000000000000000000000000000000000000000000000000000000000C99n,
			q: 0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198Fn,
			a: 0x8000000000000000000000000000000000000000000000000000000000000C96n,
			b: 0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8Bn,
			P: [
				0x0000000000000000000000000000000000000000000000000000000000000001n,
				0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFCn
			],
			длинный_хэш: false
		},
		{ // [4] GostR3410-2001-CryptoPro-C-ParamSet
			p: 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759Bn,
			q: 0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9n,
			a: 0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598n,
			b: 0x000000000000000000000000000000000000000000000000000000000000805An,
			P: [
				0x0000000000000000000000000000000000000000000000000000000000000000n,
				0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67n
			],
			длинный_хэш: false
		},
		{ // [5] tc26-gost-3410-12-256-paramSetA
			p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97n,
			q: 0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67n,
			a: 0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335n,
			b: 0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513n,
			P: [
				0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28n,
				0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5Cn
			],
			длинный_хэш: false
		},
		{ // [6] tc26-gost-3410-12-512-paramSetTest
			p: 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373n,
			q: 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DFn,
			a: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007n,
			b: 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADCn,
			P: [
				0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9An,
				0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371En
			],
			длинный_хэш: true
		},
		{ // [7] tc26-gost-3410-12-512-paramSetA
			p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7n,
			q: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275n,
			a: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4n,
			b: 0xE8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760n,
			P: [
				0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003n,
				0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4n
			],
			длинный_хэш: true
		},
		{ // [8] tc26-gost-3410-12-512-paramSetB
			p: 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006Fn,
			q: 0x800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BDn,
			a: 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006Cn,
			b: 0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116n,
			P: [
				0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002n,
				0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BDn
			],
			длинный_хэш: true
		},
		{ // [9] tc26-gost-3410-12-512-paramSetC
			p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7n,
			q: 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023EDn,
			a: 0xDC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3n,
			b: 0xB4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1n,
			P: [
				0xE2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148n,
				0xF5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40Fn
			],
			длинный_хэш: true
		}
	];

	static Согласование_ключей(
		закр, откр, доп_множ = 1n,
		{P, a, b, p, q, длинный_хэш} = this.Наборы_параметров[this.#Параметры_по_умолчанию],
		нужен_длинный_хэш
	) {
		let ключ = this.#Умножить_точку_ЭК(откр[0], откр[1], a, b, p, закр);
		if (доп_множ != 1n)
			ключ = this.#Умножить_точку_ЭК(ключ[0], ключ[1], a, b, p, доп_множ);
		const массив = [];
		for (let сч = 0; сч < (длинный_хэш ? 128 : 64); сч++) {
			const i = сч < (длинный_хэш ? 64 : 32) ? 0 : 1;
			массив.push(Number(ключ[i] & 0xFFn));
			ключ[i] >>= 8n;
		}
		if (нужен_длинный_хэш === undefined)
			нужен_длинный_хэш = длинный_хэш;
		return this.#Хэшевание.Вычислить(массив.reverse(), нужен_длинный_хэш);
	}

	static Сгенерировать_параметр_согласования(длинный_ключ = false, длинный_параметр = false) {
		let параметр;
		do параметр = this.#Случайное_число(
			длинный_параметр ? (длинный_ключ ? 256 : 128) : (длинный_ключ ? 128 : 64)
		);
		while (параметр == 0n);
		return параметр;
	}
}

module.exports = ГОСТ_ЭЦП;
