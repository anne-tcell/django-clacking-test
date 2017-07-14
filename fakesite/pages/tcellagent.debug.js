/*! tCellAgent (c) 2015 tCell.io *//*! esprima, (C) 2013 Ariya Hidayat <ariya.hidayat@gmail.com> (C) 2013 Thaddee Tyl <thaddee.tyl@gmail.com> (C) 2013 Mathias Bynens <mathias@qiwi.be>(C) 2012 Ariya Hidayat <ariya.hidayat@gmail.com>(C) 2012 Mathias Bynens <mathias@qiwi.be>(C) 2012 Joost-Wim Boekesteijn <joost-wim@boekesteijn.nl>(C) 2012 Kris Kowal <kris.kowal@cixar.com>(C) 2012 Yusuke Suzuki <utatane.tea@gmail.com>(C) 2012 Arpad Borsos <arpad.borsos@googlemail.com>(C) 2011 Ariya Hidayat <ariya.hidayat@gmail.com>, http://opensource.org/licenses/BSD-2-Clause *//*! asmCrypto, (c) 2013 Artem S Vybornov, opensource.org/licenses/MIT */function hex_sha256(s) {
    return rstr2hex(rstr_sha256(str2rstr_utf8(s)));
}

function b64_sha256(s) {
    return rstr2b64(rstr_sha256(str2rstr_utf8(s)));
}

function any_sha256(s, e) {
    return rstr2any(rstr_sha256(str2rstr_utf8(s)), e);
}

function hex_hmac_sha256(k, d) {
    return rstr2hex(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d)));
}

function b64_hmac_sha256(k, d) {
    return rstr2b64(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d)));
}

function any_hmac_sha256(k, d, e) {
    return rstr2any(rstr_hmac_sha256(str2rstr_utf8(k), str2rstr_utf8(d)), e);
}

function sha256_vm_test() {
    return "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == hex_sha256("abc").toLowerCase();
}

function rstr_sha256(s) {
    return binb2rstr(binb_sha256(rstr2binb(s), 8 * s.length));
}

function rstr_hmac_sha256(key, data) {
    var bkey = rstr2binb(key);
    bkey.length > 16 && (bkey = binb_sha256(bkey, 8 * key.length));
    for (var ipad = Array(16), opad = Array(16), i = 0; i < 16; i++) ipad[i] = 909522486 ^ bkey[i], 
    opad[i] = 1549556828 ^ bkey[i];
    var hash = binb_sha256(ipad.concat(rstr2binb(data)), 512 + 8 * data.length);
    return binb2rstr(binb_sha256(opad.concat(hash), 768));
}

function rstr2hex(input) {
    for (var x, hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef", output = "", i = 0; i < input.length; i++) x = input.charCodeAt(i), 
    output += hex_tab.charAt(x >>> 4 & 15) + hex_tab.charAt(15 & x);
    return output;
}

function rstr2b64(input) {
    for (var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", output = "", len = input.length, i = 0; i < len; i += 3) for (var triplet = input.charCodeAt(i) << 16 | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0), j = 0; j < 4; j++) 8 * i + 6 * j > 8 * input.length ? output += b64pad : output += tab.charAt(triplet >>> 6 * (3 - j) & 63);
    return output;
}

function rstr2any(input, encoding) {
    var i, q, x, quotient, divisor = encoding.length, remainders = Array(), dividend = Array(Math.ceil(input.length / 2));
    for (i = 0; i < dividend.length; i++) dividend[i] = input.charCodeAt(2 * i) << 8 | input.charCodeAt(2 * i + 1);
    for (;dividend.length > 0; ) {
        for (quotient = Array(), x = 0, i = 0; i < dividend.length; i++) x = (x << 16) + dividend[i], 
        q = Math.floor(x / divisor), x -= q * divisor, (quotient.length > 0 || q > 0) && (quotient[quotient.length] = q);
        remainders[remainders.length] = x, dividend = quotient;
    }
    var output = "";
    for (i = remainders.length - 1; i >= 0; i--) output += encoding.charAt(remainders[i]);
    var full_length = Math.ceil(8 * input.length / (Math.log(encoding.length) / Math.log(2)));
    for (i = output.length; i < full_length; i++) output = encoding[0] + output;
    return output;
}

function str2rstr_utf8(input) {
    for (var x, y, output = "", i = -1; ++i < input.length; ) x = input.charCodeAt(i), 
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0, 55296 <= x && x <= 56319 && 56320 <= y && y <= 57343 && (x = 65536 + ((1023 & x) << 10) + (1023 & y), 
    i++), x <= 127 ? output += String.fromCharCode(x) : x <= 2047 ? output += String.fromCharCode(192 | x >>> 6 & 31, 128 | 63 & x) : x <= 65535 ? output += String.fromCharCode(224 | x >>> 12 & 15, 128 | x >>> 6 & 63, 128 | 63 & x) : x <= 2097151 && (output += String.fromCharCode(240 | x >>> 18 & 7, 128 | x >>> 12 & 63, 128 | x >>> 6 & 63, 128 | 63 & x));
    return output;
}

function str2rstr_utf16le(input) {
    for (var output = "", i = 0; i < input.length; i++) output += String.fromCharCode(255 & input.charCodeAt(i), input.charCodeAt(i) >>> 8 & 255);
    return output;
}

function str2rstr_utf16be(input) {
    for (var output = "", i = 0; i < input.length; i++) output += String.fromCharCode(input.charCodeAt(i) >>> 8 & 255, 255 & input.charCodeAt(i));
    return output;
}

function rstr2binb(input) {
    for (var output = Array(input.length >> 2), i = 0; i < output.length; i++) output[i] = 0;
    for (var i = 0; i < 8 * input.length; i += 8) output[i >> 5] |= (255 & input.charCodeAt(i / 8)) << 24 - i % 32;
    return output;
}

function binb2rstr(input) {
    for (var output = "", i = 0; i < 32 * input.length; i += 8) output += String.fromCharCode(input[i >> 5] >>> 24 - i % 32 & 255);
    return output;
}

function sha256_S(X, n) {
    return X >>> n | X << 32 - n;
}

function sha256_R(X, n) {
    return X >>> n;
}

function sha256_Ch(x, y, z) {
    return x & y ^ ~x & z;
}

function sha256_Maj(x, y, z) {
    return x & y ^ x & z ^ y & z;
}

function sha256_Sigma0256(x) {
    return sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22);
}

function sha256_Sigma1256(x) {
    return sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25);
}

function sha256_Gamma0256(x) {
    return sha256_S(x, 7) ^ sha256_S(x, 18) ^ sha256_R(x, 3);
}

function sha256_Gamma1256(x) {
    return sha256_S(x, 17) ^ sha256_S(x, 19) ^ sha256_R(x, 10);
}

function sha256_Sigma0512(x) {
    return sha256_S(x, 28) ^ sha256_S(x, 34) ^ sha256_S(x, 39);
}

function sha256_Sigma1512(x) {
    return sha256_S(x, 14) ^ sha256_S(x, 18) ^ sha256_S(x, 41);
}

function sha256_Gamma0512(x) {
    return sha256_S(x, 1) ^ sha256_S(x, 8) ^ sha256_R(x, 7);
}

function sha256_Gamma1512(x) {
    return sha256_S(x, 19) ^ sha256_S(x, 61) ^ sha256_R(x, 6);
}

function binb_sha256(m, l) {
    var a, b, c, d, e, f, g, h, i, j, T1, T2, HASH = new Array(1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225), W = new Array(64);
    for (m[l >> 5] |= 128 << 24 - l % 32, m[15 + (l + 64 >> 9 << 4)] = l, i = 0; i < m.length; i += 16) {
        for (a = HASH[0], b = HASH[1], c = HASH[2], d = HASH[3], e = HASH[4], f = HASH[5], 
        g = HASH[6], h = HASH[7], j = 0; j < 64; j++) W[j] = j < 16 ? m[j + i] : safe_add(safe_add(safe_add(sha256_Gamma1256(W[j - 2]), W[j - 7]), sha256_Gamma0256(W[j - 15])), W[j - 16]), 
        T1 = safe_add(safe_add(safe_add(safe_add(h, sha256_Sigma1256(e)), sha256_Ch(e, f, g)), sha256_K[j]), W[j]), 
        T2 = safe_add(sha256_Sigma0256(a), sha256_Maj(a, b, c)), h = g, g = f, f = e, e = safe_add(d, T1), 
        d = c, c = b, b = a, a = safe_add(T1, T2);
        HASH[0] = safe_add(a, HASH[0]), HASH[1] = safe_add(b, HASH[1]), HASH[2] = safe_add(c, HASH[2]), 
        HASH[3] = safe_add(d, HASH[3]), HASH[4] = safe_add(e, HASH[4]), HASH[5] = safe_add(f, HASH[5]), 
        HASH[6] = safe_add(g, HASH[6]), HASH[7] = safe_add(h, HASH[7]);
    }
    return HASH;
}

function safe_add(x, y) {
    var lsw = (65535 & x) + (65535 & y);
    return (x >> 16) + (y >> 16) + (lsw >> 16) << 16 | 65535 & lsw;
}

function ScriptSignature(hashType, hash) {
    this.hash = hash, this.hashType = hashType;
}

function ScriptSignatureProcessor(report_callback) {
    this.report_callback = report_callback, this.is_ready = !1, this.scriptElementQueue = [], 
    this.attributesQueue = [], this.scriptStringQueue = [], this.javascriptPrefixLength = "javascript:".length, 
    this.javascriptPrefixDecodeElement = document.createElement("textarea"), this.attribNames = attribNames;
}

var esprima = function() {
    "use strict";
    function assert(condition, message) {
        if (!condition) throw new Error("ASSERT: " + message);
    }
    function isDecimalDigit(ch) {
        return ch >= 48 && ch <= 57;
    }
    function isHexDigit(ch) {
        return "0123456789abcdefABCDEF".indexOf(ch) >= 0;
    }
    function isOctalDigit(ch) {
        return "01234567".indexOf(ch) >= 0;
    }
    function octalToDecimal(ch) {
        var octal = "0" !== ch, code = "01234567".indexOf(ch);
        return index < length && isOctalDigit(source[index]) && (octal = !0, code = 8 * code + "01234567".indexOf(source[index++]), 
        "0123".indexOf(ch) >= 0 && index < length && isOctalDigit(source[index]) && (code = 8 * code + "01234567".indexOf(source[index++]))), 
        {
            code: code,
            octal: octal
        };
    }
    function isWhiteSpace(ch) {
        return 32 === ch || 9 === ch || 11 === ch || 12 === ch || 160 === ch || ch >= 5760 && [ 5760, 6158, 8192, 8193, 8194, 8195, 8196, 8197, 8198, 8199, 8200, 8201, 8202, 8239, 8287, 12288, 65279 ].indexOf(ch) >= 0;
    }
    function isLineTerminator(ch) {
        return 10 === ch || 13 === ch || 8232 === ch || 8233 === ch;
    }
    function isIdentifierStart(ch) {
        return 36 === ch || 95 === ch || ch >= 65 && ch <= 90 || ch >= 97 && ch <= 122 || 92 === ch || ch >= 128 && Regex.NonAsciiIdentifierStart.test(String.fromCharCode(ch));
    }
    function isIdentifierPart(ch) {
        return 36 === ch || 95 === ch || ch >= 65 && ch <= 90 || ch >= 97 && ch <= 122 || ch >= 48 && ch <= 57 || 92 === ch || ch >= 128 && Regex.NonAsciiIdentifierPart.test(String.fromCharCode(ch));
    }
    function isFutureReservedWord(id) {
        switch (id) {
          case "enum":
          case "export":
          case "import":
          case "super":
            return !0;

          default:
            return !1;
        }
    }
    function isStrictModeReservedWord(id) {
        switch (id) {
          case "implements":
          case "interface":
          case "package":
          case "private":
          case "protected":
          case "public":
          case "static":
          case "yield":
          case "let":
            return !0;

          default:
            return !1;
        }
    }
    function isRestrictedWord(id) {
        return "eval" === id || "arguments" === id;
    }
    function isKeyword(id) {
        switch (id.length) {
          case 2:
            return "if" === id || "in" === id || "do" === id;

          case 3:
            return "var" === id || "for" === id || "new" === id || "try" === id || "let" === id;

          case 4:
            return "this" === id || "else" === id || "case" === id || "void" === id || "with" === id || "enum" === id;

          case 5:
            return "while" === id || "break" === id || "catch" === id || "throw" === id || "const" === id || "yield" === id || "class" === id || "super" === id;

          case 6:
            return "return" === id || "typeof" === id || "delete" === id || "switch" === id || "export" === id || "import" === id;

          case 7:
            return "default" === id || "finally" === id || "extends" === id;

          case 8:
            return "function" === id || "continue" === id || "debugger" === id;

          case 10:
            return "instanceof" === id;

          default:
            return !1;
        }
    }
    function addComment(type, value, start, end, loc) {
        var comment;
        assert("number" == typeof start, "Comment must have valid position"), state.lastCommentStart = start, 
        comment = {
            type: type,
            value: value
        }, extra.range && (comment.range = [ start, end ]), extra.loc && (comment.loc = loc), 
        extra.comments.push(comment), extra.attachComment && (extra.leadingComments.push(comment), 
        extra.trailingComments.push(comment));
    }
    function skipSingleLineComment(offset) {
        var start, loc, ch, comment;
        for (start = index - offset, loc = {
            start: {
                line: lineNumber,
                column: index - lineStart - offset
            }
        }; index < length; ) if (ch = source.charCodeAt(index), ++index, isLineTerminator(ch)) return hasLineTerminator = !0, 
        extra.comments && (comment = source.slice(start + offset, index - 1), loc.end = {
            line: lineNumber,
            column: index - lineStart - 1
        }, addComment("Line", comment, start, index - 1, loc)), 13 === ch && 10 === source.charCodeAt(index) && ++index, 
        ++lineNumber, void (lineStart = index);
        extra.comments && (comment = source.slice(start + offset, index), loc.end = {
            line: lineNumber,
            column: index - lineStart
        }, addComment("Line", comment, start, index, loc));
    }
    function skipMultiLineComment() {
        var start, loc, ch, comment;
        for (extra.comments && (start = index - 2, loc = {
            start: {
                line: lineNumber,
                column: index - lineStart - 2
            }
        }); index < length; ) if (ch = source.charCodeAt(index), isLineTerminator(ch)) 13 === ch && 10 === source.charCodeAt(index + 1) && ++index, 
        hasLineTerminator = !0, ++lineNumber, ++index, lineStart = index; else if (42 === ch) {
            if (47 === source.charCodeAt(index + 1)) return ++index, ++index, void (extra.comments && (comment = source.slice(start + 2, index - 2), 
            loc.end = {
                line: lineNumber,
                column: index - lineStart
            }, addComment("Block", comment, start, index, loc)));
            ++index;
        } else ++index;
        extra.comments && (loc.end = {
            line: lineNumber,
            column: index - lineStart
        }, comment = source.slice(start + 2, index), addComment("Block", comment, start, index, loc)), 
        tolerateUnexpectedToken();
    }
    function skipComment() {
        var ch, start;
        for (hasLineTerminator = !1, start = 0 === index; index < length; ) if (ch = source.charCodeAt(index), 
        isWhiteSpace(ch)) ++index; else if (isLineTerminator(ch)) hasLineTerminator = !0, 
        ++index, 13 === ch && 10 === source.charCodeAt(index) && ++index, ++lineNumber, 
        lineStart = index, start = !0; else if (47 === ch) if (47 === (ch = source.charCodeAt(index + 1))) ++index, 
        ++index, skipSingleLineComment(2), start = !0; else {
            if (42 !== ch) break;
            ++index, ++index, skipMultiLineComment();
        } else if (start && 45 === ch) {
            if (45 !== source.charCodeAt(index + 1) || 62 !== source.charCodeAt(index + 2)) break;
            index += 3, skipSingleLineComment(3);
        } else {
            if (60 !== ch) break;
            if ("!--" !== source.slice(index + 1, index + 4)) break;
            ++index, ++index, ++index, ++index, skipSingleLineComment(4);
        }
    }
    function scanHexEscape(prefix) {
        var i, len, ch, code = 0;
        for (len = "u" === prefix ? 4 : 2, i = 0; i < len; ++i) {
            if (!(index < length && isHexDigit(source[index]))) return "";
            ch = source[index++], code = 16 * code + "0123456789abcdef".indexOf(ch.toLowerCase());
        }
        return String.fromCharCode(code);
    }
    function scanUnicodeCodePointEscape() {
        var ch, code, cu1, cu2;
        for (ch = source[index], code = 0, "}" === ch && throwUnexpectedToken(); index < length && (ch = source[index++], 
        isHexDigit(ch)); ) code = 16 * code + "0123456789abcdef".indexOf(ch.toLowerCase());
        return (code > 1114111 || "}" !== ch) && throwUnexpectedToken(), code <= 65535 ? String.fromCharCode(code) : (cu1 = 55296 + (code - 65536 >> 10), 
        cu2 = 56320 + (code - 65536 & 1023), String.fromCharCode(cu1, cu2));
    }
    function getEscapedIdentifier() {
        var ch, id;
        for (ch = source.charCodeAt(index++), id = String.fromCharCode(ch), 92 === ch && (117 !== source.charCodeAt(index) && throwUnexpectedToken(), 
        ++index, ch = scanHexEscape("u"), ch && "\\" !== ch && isIdentifierStart(ch.charCodeAt(0)) || throwUnexpectedToken(), 
        id = ch); index < length && (ch = source.charCodeAt(index), isIdentifierPart(ch)); ) ++index, 
        id += String.fromCharCode(ch), 92 === ch && (id = id.substr(0, id.length - 1), 117 !== source.charCodeAt(index) && throwUnexpectedToken(), 
        ++index, ch = scanHexEscape("u"), ch && "\\" !== ch && isIdentifierPart(ch.charCodeAt(0)) || throwUnexpectedToken(), 
        id += ch);
        return id;
    }
    function getIdentifier() {
        var start, ch;
        for (start = index++; index < length; ) {
            if (92 === (ch = source.charCodeAt(index))) return index = start, getEscapedIdentifier();
            if (!isIdentifierPart(ch)) break;
            ++index;
        }
        return source.slice(start, index);
    }
    function scanIdentifier() {
        var start, id, type;
        return start = index, id = 92 === source.charCodeAt(index) ? getEscapedIdentifier() : getIdentifier(), 
        type = 1 === id.length ? Token.Identifier : isKeyword(id) ? Token.Keyword : "null" === id ? Token.NullLiteral : "true" === id || "false" === id ? Token.BooleanLiteral : Token.Identifier, 
        {
            type: type,
            value: id,
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function scanPunctuator() {
        var token, str;
        switch (token = {
            type: Token.Punctuator,
            value: "",
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: index,
            end: index
        }, str = source[index]) {
          case "(":
            extra.tokenize && (extra.openParenToken = extra.tokens.length), ++index;
            break;

          case "{":
            extra.tokenize && (extra.openCurlyToken = extra.tokens.length), state.curlyStack.push("{"), 
            ++index;
            break;

          case ".":
            ++index, "." === source[index] && "." === source[index + 1] && (index += 2, str = "...");
            break;

          case "}":
            ++index, state.curlyStack.pop();
            break;

          case ")":
          case ";":
          case ",":
          case "[":
          case "]":
          case ":":
          case "?":
          case "~":
            ++index;
            break;

          default:
            str = source.substr(index, 4), ">>>=" === str ? index += 4 : (str = str.substr(0, 3), 
            "===" === str || "!==" === str || ">>>" === str || "<<=" === str || ">>=" === str ? index += 3 : (str = str.substr(0, 2), 
            "&&" === str || "||" === str || "==" === str || "!=" === str || "+=" === str || "-=" === str || "*=" === str || "/=" === str || "++" === str || "--" === str || "<<" === str || ">>" === str || "&=" === str || "|=" === str || "^=" === str || "%=" === str || "<=" === str || ">=" === str || "=>" === str ? index += 2 : (str = source[index], 
            "<>=!+-*%&|^/".indexOf(str) >= 0 && ++index)));
        }
        return index === token.start && throwUnexpectedToken(), token.end = index, token.value = str, 
        token;
    }
    function scanHexLiteral(start) {
        for (var number = ""; index < length && isHexDigit(source[index]); ) number += source[index++];
        return 0 === number.length && throwUnexpectedToken(), isIdentifierStart(source.charCodeAt(index)) && throwUnexpectedToken(), 
        {
            type: Token.NumericLiteral,
            value: parseInt("0x" + number, 16),
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function scanBinaryLiteral(start) {
        var ch, number;
        for (number = ""; index < length && ("0" === (ch = source[index]) || "1" === ch); ) number += source[index++];
        return 0 === number.length && throwUnexpectedToken(), index < length && (ch = source.charCodeAt(index), 
        (isIdentifierStart(ch) || isDecimalDigit(ch)) && throwUnexpectedToken()), {
            type: Token.NumericLiteral,
            value: parseInt(number, 2),
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function scanOctalLiteral(prefix, start) {
        var number, octal;
        for (isOctalDigit(prefix) ? (octal = !0, number = "0" + source[index++]) : (octal = !1, 
        ++index, number = ""); index < length && isOctalDigit(source[index]); ) number += source[index++];
        return octal || 0 !== number.length || throwUnexpectedToken(), (isIdentifierStart(source.charCodeAt(index)) || isDecimalDigit(source.charCodeAt(index))) && throwUnexpectedToken(), 
        {
            type: Token.NumericLiteral,
            value: parseInt(number, 8),
            octal: octal,
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function isImplicitOctalLiteral() {
        var i, ch;
        for (i = index + 1; i < length; ++i) {
            if ("8" === (ch = source[i]) || "9" === ch) return !1;
            if (!isOctalDigit(ch)) return !0;
        }
        return !0;
    }
    function scanNumericLiteral() {
        var number, start, ch;
        if (ch = source[index], assert(isDecimalDigit(ch.charCodeAt(0)) || "." === ch, "Numeric literal must start with a decimal digit or a decimal point"), 
        start = index, number = "", "." !== ch) {
            if (number = source[index++], ch = source[index], "0" === number) {
                if ("x" === ch || "X" === ch) return ++index, scanHexLiteral(start);
                if ("b" === ch || "B" === ch) return ++index, scanBinaryLiteral(start);
                if ("o" === ch || "O" === ch) return scanOctalLiteral(ch, start);
                if (isOctalDigit(ch) && isImplicitOctalLiteral()) return scanOctalLiteral(ch, start);
            }
            for (;isDecimalDigit(source.charCodeAt(index)); ) number += source[index++];
            ch = source[index];
        }
        if ("." === ch) {
            for (number += source[index++]; isDecimalDigit(source.charCodeAt(index)); ) number += source[index++];
            ch = source[index];
        }
        if ("e" === ch || "E" === ch) if (number += source[index++], ch = source[index], 
        "+" !== ch && "-" !== ch || (number += source[index++]), isDecimalDigit(source.charCodeAt(index))) for (;isDecimalDigit(source.charCodeAt(index)); ) number += source[index++]; else throwUnexpectedToken();
        return isIdentifierStart(source.charCodeAt(index)) && throwUnexpectedToken(), {
            type: Token.NumericLiteral,
            value: parseFloat(number),
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function scanStringLiteral() {
        var quote, start, ch, unescaped, octToDec, str = "", octal = !1;
        for (quote = source[index], assert("'" === quote || '"' === quote, "String literal must starts with a quote"), 
        start = index, ++index; index < length; ) {
            if ((ch = source[index++]) === quote) {
                quote = "";
                break;
            }
            if ("\\" === ch) if ((ch = source[index++]) && isLineTerminator(ch.charCodeAt(0))) ++lineNumber, 
            "\r" === ch && "\n" === source[index] && ++index, lineStart = index; else switch (ch) {
              case "u":
              case "x":
                if ("{" === source[index]) ++index, str += scanUnicodeCodePointEscape(); else {
                    if (!(unescaped = scanHexEscape(ch))) throw throwUnexpectedToken();
                    str += unescaped;
                }
                break;

              case "n":
                str += "\n";
                break;

              case "r":
                str += "\r";
                break;

              case "t":
                str += "\t";
                break;

              case "b":
                str += "\b";
                break;

              case "f":
                str += "\f";
                break;

              case "v":
                str += "\v";
                break;

              case "8":
              case "9":
                throw throwUnexpectedToken();

              default:
                isOctalDigit(ch) ? (octToDec = octalToDecimal(ch), octal = octToDec.octal || octal, 
                str += String.fromCharCode(octToDec.code)) : str += ch;
            } else {
                if (isLineTerminator(ch.charCodeAt(0))) break;
                str += ch;
            }
        }
        return "" !== quote && throwUnexpectedToken(), {
            type: Token.StringLiteral,
            value: str,
            octal: octal,
            lineNumber: startLineNumber,
            lineStart: startLineStart,
            start: start,
            end: index
        };
    }
    function scanTemplate() {
        var ch, start, rawOffset, terminated, head, tail, restore, unescaped, cooked = "";
        for (terminated = !1, tail = !1, start = index, head = "`" === source[index], rawOffset = 2, 
        ++index; index < length; ) {
            if ("`" === (ch = source[index++])) {
                rawOffset = 1, tail = !0, terminated = !0;
                break;
            }
            if ("$" === ch) {
                if ("{" === source[index]) {
                    state.curlyStack.push("${"), ++index, terminated = !0;
                    break;
                }
                cooked += ch;
            } else if ("\\" === ch) if (ch = source[index++], isLineTerminator(ch.charCodeAt(0))) ++lineNumber, 
            "\r" === ch && "\n" === source[index] && ++index, lineStart = index; else switch (ch) {
              case "n":
                cooked += "\n";
                break;

              case "r":
                cooked += "\r";
                break;

              case "t":
                cooked += "\t";
                break;

              case "u":
              case "x":
                "{" === source[index] ? (++index, cooked += scanUnicodeCodePointEscape()) : (restore = index, 
                unescaped = scanHexEscape(ch), unescaped ? cooked += unescaped : (index = restore, 
                cooked += ch));
                break;

              case "b":
                cooked += "\b";
                break;

              case "f":
                cooked += "\f";
                break;

              case "v":
                cooked += "\v";
                break;

              default:
                "0" === ch ? (isDecimalDigit(source.charCodeAt(index)) && throwError(Messages.TemplateOctalLiteral), 
                cooked += "\0") : isOctalDigit(ch) ? throwError(Messages.TemplateOctalLiteral) : cooked += ch;
            } else isLineTerminator(ch.charCodeAt(0)) ? (++lineNumber, "\r" === ch && "\n" === source[index] && ++index, 
            lineStart = index, cooked += "\n") : cooked += ch;
        }
        return terminated || throwUnexpectedToken(), head || state.curlyStack.pop(), {
            type: Token.Template,
            value: {
                cooked: cooked,
                raw: source.slice(start + 1, index - rawOffset)
            },
            head: head,
            tail: tail,
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        };
    }
    function testRegExp(pattern, flags) {
        var tmp = pattern;
        flags.indexOf("u") >= 0 && (tmp = tmp.replace(/\\u\{([0-9a-fA-F]+)\}/g, function($0, $1) {
            if (parseInt($1, 16) <= 1114111) return "x";
            throwUnexpectedToken(null, Messages.InvalidRegExp);
        }).replace(/\\u([a-fA-F0-9]{4})|[\uD800-\uDBFF][\uDC00-\uDFFF]/g, "x"));
        try {
            RegExp(tmp);
        } catch (e) {
            throwUnexpectedToken(null, Messages.InvalidRegExp);
        }
        try {
            return new RegExp(pattern, flags);
        } catch (exception) {
            return null;
        }
    }
    function scanRegExpBody() {
        var ch, str, classMarker, terminated, body;
        for (ch = source[index], assert("/" === ch, "Regular expression literal must start with a slash"), 
        str = source[index++], classMarker = !1, terminated = !1; index < length; ) if (ch = source[index++], 
        str += ch, "\\" === ch) ch = source[index++], isLineTerminator(ch.charCodeAt(0)) && throwUnexpectedToken(null, Messages.UnterminatedRegExp), 
        str += ch; else if (isLineTerminator(ch.charCodeAt(0))) throwUnexpectedToken(null, Messages.UnterminatedRegExp); else if (classMarker) "]" === ch && (classMarker = !1); else {
            if ("/" === ch) {
                terminated = !0;
                break;
            }
            "[" === ch && (classMarker = !0);
        }
        return terminated || throwUnexpectedToken(null, Messages.UnterminatedRegExp), body = str.substr(1, str.length - 2), 
        {
            value: body,
            literal: str
        };
    }
    function scanRegExpFlags() {
        var ch, str, flags, restore;
        for (str = "", flags = ""; index < length && (ch = source[index], isIdentifierPart(ch.charCodeAt(0))); ) if (++index, 
        "\\" === ch && index < length) if ("u" === (ch = source[index])) {
            if (++index, restore = index, ch = scanHexEscape("u")) for (flags += ch, str += "\\u"; restore < index; ++restore) str += source[restore]; else index = restore, 
            flags += "u", str += "\\u";
            tolerateUnexpectedToken();
        } else str += "\\", tolerateUnexpectedToken(); else flags += ch, str += ch;
        return {
            value: flags,
            literal: str
        };
    }
    function scanRegExp() {
        scanning = !0;
        var start, body, flags, value;
        return lookahead = null, skipComment(), start = index, body = scanRegExpBody(), 
        flags = scanRegExpFlags(), value = testRegExp(body.value, flags.value), scanning = !1, 
        extra.tokenize ? {
            type: Token.RegularExpression,
            value: value,
            regex: {
                pattern: body.value,
                flags: flags.value
            },
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: start,
            end: index
        } : {
            literal: body.literal + flags.literal,
            value: value,
            regex: {
                pattern: body.value,
                flags: flags.value
            },
            start: start,
            end: index
        };
    }
    function collectRegex() {
        var pos, loc, regex, token;
        return skipComment(), pos = index, loc = {
            start: {
                line: lineNumber,
                column: index - lineStart
            }
        }, regex = scanRegExp(), loc.end = {
            line: lineNumber,
            column: index - lineStart
        }, extra.tokenize || (extra.tokens.length > 0 && (token = extra.tokens[extra.tokens.length - 1], 
        token.range[0] === pos && "Punctuator" === token.type && ("/" !== token.value && "/=" !== token.value || extra.tokens.pop())), 
        extra.tokens.push({
            type: "RegularExpression",
            value: regex.literal,
            regex: regex.regex,
            range: [ pos, index ],
            loc: loc
        })), regex;
    }
    function isIdentifierName(token) {
        return token.type === Token.Identifier || token.type === Token.Keyword || token.type === Token.BooleanLiteral || token.type === Token.NullLiteral;
    }
    function advanceSlash() {
        var prevToken, checkToken;
        if (!(prevToken = extra.tokens[extra.tokens.length - 1])) return collectRegex();
        if ("Punctuator" === prevToken.type) {
            if ("]" === prevToken.value) return scanPunctuator();
            if (")" === prevToken.value) return checkToken = extra.tokens[extra.openParenToken - 1], 
            !checkToken || "Keyword" !== checkToken.type || "if" !== checkToken.value && "while" !== checkToken.value && "for" !== checkToken.value && "with" !== checkToken.value ? scanPunctuator() : collectRegex();
            if ("}" === prevToken.value) {
                if (extra.tokens[extra.openCurlyToken - 3] && "Keyword" === extra.tokens[extra.openCurlyToken - 3].type) {
                    if (!(checkToken = extra.tokens[extra.openCurlyToken - 4])) return scanPunctuator();
                } else {
                    if (!extra.tokens[extra.openCurlyToken - 4] || "Keyword" !== extra.tokens[extra.openCurlyToken - 4].type) return scanPunctuator();
                    if (!(checkToken = extra.tokens[extra.openCurlyToken - 5])) return collectRegex();
                }
                return FnExprTokens.indexOf(checkToken.value) >= 0 ? scanPunctuator() : collectRegex();
            }
            return collectRegex();
        }
        return "Keyword" === prevToken.type && "this" !== prevToken.value ? collectRegex() : scanPunctuator();
    }
    function advance() {
        var ch, token;
        return index >= length ? {
            type: Token.EOF,
            lineNumber: lineNumber,
            lineStart: lineStart,
            start: index,
            end: index
        } : (ch = source.charCodeAt(index), isIdentifierStart(ch) ? (token = scanIdentifier(), 
        strict && isStrictModeReservedWord(token.value) && (token.type = Token.Keyword), 
        token) : 40 === ch || 41 === ch || 59 === ch ? scanPunctuator() : 39 === ch || 34 === ch ? scanStringLiteral() : 46 === ch ? isDecimalDigit(source.charCodeAt(index + 1)) ? scanNumericLiteral() : scanPunctuator() : isDecimalDigit(ch) ? scanNumericLiteral() : extra.tokenize && 47 === ch ? advanceSlash() : 96 === ch || 125 === ch && "${" === state.curlyStack[state.curlyStack.length - 1] ? scanTemplate() : scanPunctuator());
    }
    function collectToken() {
        var loc, token, value, entry;
        return loc = {
            start: {
                line: lineNumber,
                column: index - lineStart
            }
        }, token = advance(), loc.end = {
            line: lineNumber,
            column: index - lineStart
        }, token.type !== Token.EOF && (value = source.slice(token.start, token.end), entry = {
            type: TokenName[token.type],
            value: value,
            range: [ token.start, token.end ],
            loc: loc
        }, token.regex && (entry.regex = {
            pattern: token.regex.pattern,
            flags: token.regex.flags
        }), extra.tokens.push(entry)), token;
    }
    function lex() {
        var token;
        return scanning = !0, lastIndex = index, lastLineNumber = lineNumber, lastLineStart = lineStart, 
        skipComment(), token = lookahead, startIndex = index, startLineNumber = lineNumber, 
        startLineStart = lineStart, lookahead = void 0 !== extra.tokens ? collectToken() : advance(), 
        scanning = !1, token;
    }
    function peek() {
        scanning = !0, skipComment(), lastIndex = index, lastLineNumber = lineNumber, lastLineStart = lineStart, 
        startIndex = index, startLineNumber = lineNumber, startLineStart = lineStart, lookahead = void 0 !== extra.tokens ? collectToken() : advance(), 
        scanning = !1;
    }
    function Position() {
        this.line = startLineNumber, this.column = startIndex - startLineStart;
    }
    function SourceLocation() {
        this.start = new Position(), this.end = null;
    }
    function WrappingSourceLocation(startToken) {
        this.start = {
            line: startToken.lineNumber,
            column: startToken.start - startToken.lineStart
        }, this.end = null;
    }
    function Node() {
        extra.range && (this.range = [ startIndex, 0 ]), extra.loc && (this.loc = new SourceLocation());
    }
    function WrappingNode(startToken) {
        extra.range && (this.range = [ startToken.start, 0 ]), extra.loc && (this.loc = new WrappingSourceLocation(startToken));
    }
    function recordError(error) {
        var e, existing;
        for (e = 0; e < extra.errors.length; e++) if (existing = extra.errors[e], existing.index === error.index && existing.message === error.message) return;
        extra.errors.push(error);
    }
    function createError(line, pos, description) {
        var error = new Error("Line " + line + ": " + description);
        return error.index = pos, error.lineNumber = line, error.column = pos - (scanning ? lineStart : lastLineStart) + 1, 
        error.description = description, error;
    }
    function throwError(messageFormat) {
        var args, msg;
        throw args = Array.prototype.slice.call(arguments, 1), msg = messageFormat.replace(/%(\d)/g, function(whole, idx) {
            return assert(idx < args.length, "Message reference must be in range"), args[idx];
        }), createError(lastLineNumber, lastIndex, msg);
    }
    function tolerateError(messageFormat) {
        var args, msg, error;
        if (args = Array.prototype.slice.call(arguments, 1), msg = messageFormat.replace(/%(\d)/g, function(whole, idx) {
            return assert(idx < args.length, "Message reference must be in range"), args[idx];
        }), error = createError(lineNumber, lastIndex, msg), !extra.errors) throw error;
        recordError(error);
    }
    function unexpectedTokenError(token, message) {
        var value, msg = message || Messages.UnexpectedToken;
        return token ? (message || (msg = token.type === Token.EOF ? Messages.UnexpectedEOS : token.type === Token.Identifier ? Messages.UnexpectedIdentifier : token.type === Token.NumericLiteral ? Messages.UnexpectedNumber : token.type === Token.StringLiteral ? Messages.UnexpectedString : token.type === Token.Template ? Messages.UnexpectedTemplate : Messages.UnexpectedToken, 
        token.type === Token.Keyword && (isFutureReservedWord(token.value) ? msg = Messages.UnexpectedReserved : strict && isStrictModeReservedWord(token.value) && (msg = Messages.StrictReservedWord))), 
        value = token.type === Token.Template ? token.value.raw : token.value) : value = "ILLEGAL", 
        msg = msg.replace("%0", value), token && "number" == typeof token.lineNumber ? createError(token.lineNumber, token.start, msg) : createError(scanning ? lineNumber : lastLineNumber, scanning ? index : lastIndex, msg);
    }
    function throwUnexpectedToken(token, message) {
        throw unexpectedTokenError(token, message);
    }
    function tolerateUnexpectedToken(token, message) {
        var error = unexpectedTokenError(token, message);
        if (!extra.errors) throw error;
        recordError(error);
    }
    function expect(value) {
        var token = lex();
        token.type === Token.Punctuator && token.value === value || throwUnexpectedToken(token);
    }
    function expectCommaSeparator() {
        var token;
        extra.errors ? (token = lookahead, token.type === Token.Punctuator && "," === token.value ? lex() : token.type === Token.Punctuator && ";" === token.value ? (lex(), 
        tolerateUnexpectedToken(token)) : tolerateUnexpectedToken(token, Messages.UnexpectedToken)) : expect(",");
    }
    function expectKeyword(keyword) {
        var token = lex();
        token.type === Token.Keyword && token.value === keyword || throwUnexpectedToken(token);
    }
    function match(value) {
        return lookahead.type === Token.Punctuator && lookahead.value === value;
    }
    function matchKeyword(keyword) {
        return lookahead.type === Token.Keyword && lookahead.value === keyword;
    }
    function matchContextualKeyword(keyword) {
        return lookahead.type === Token.Identifier && lookahead.value === keyword;
    }
    function matchAssign() {
        var op;
        return lookahead.type === Token.Punctuator && ("=" === (op = lookahead.value) || "*=" === op || "/=" === op || "%=" === op || "+=" === op || "-=" === op || "<<=" === op || ">>=" === op || ">>>=" === op || "&=" === op || "^=" === op || "|=" === op);
    }
    function consumeSemicolon() {
        if (59 === source.charCodeAt(startIndex) || match(";")) return void lex();
        hasLineTerminator || (lastIndex = startIndex, lastLineNumber = startLineNumber, 
        lastLineStart = startLineStart, lookahead.type === Token.EOF || match("}") || throwUnexpectedToken(lookahead));
    }
    function isolateCoverGrammar(parser) {
        var result, oldIsBindingElement = isBindingElement, oldIsAssignmentTarget = isAssignmentTarget, oldFirstCoverInitializedNameError = firstCoverInitializedNameError;
        return isBindingElement = !0, isAssignmentTarget = !0, firstCoverInitializedNameError = null, 
        result = parser(), null !== firstCoverInitializedNameError && throwUnexpectedToken(firstCoverInitializedNameError), 
        isBindingElement = oldIsBindingElement, isAssignmentTarget = oldIsAssignmentTarget, 
        firstCoverInitializedNameError = oldFirstCoverInitializedNameError, result;
    }
    function inheritCoverGrammar(parser) {
        var result, oldIsBindingElement = isBindingElement, oldIsAssignmentTarget = isAssignmentTarget, oldFirstCoverInitializedNameError = firstCoverInitializedNameError;
        return isBindingElement = !0, isAssignmentTarget = !0, firstCoverInitializedNameError = null, 
        result = parser(), isBindingElement = isBindingElement && oldIsBindingElement, isAssignmentTarget = isAssignmentTarget && oldIsAssignmentTarget, 
        firstCoverInitializedNameError = oldFirstCoverInitializedNameError || firstCoverInitializedNameError, 
        result;
    }
    function parseArrayPattern() {
        var rest, restNode, node = new Node(), elements = [];
        for (expect("["); !match("]"); ) if (match(",")) lex(), elements.push(null); else {
            if (match("...")) {
                restNode = new Node(), lex(), rest = parseVariableIdentifier(), elements.push(restNode.finishRestElement(rest));
                break;
            }
            elements.push(parsePatternWithDefault()), match("]") || expect(",");
        }
        return expect("]"), node.finishArrayPattern(elements);
    }
    function parsePropertyPattern() {
        var key, init, node = new Node(), computed = match("[");
        if (lookahead.type === Token.Identifier) {
            if (key = parseVariableIdentifier(), match("=")) return lex(), init = parseAssignmentExpression(), 
            node.finishProperty("init", key, !1, new WrappingNode(key).finishAssignmentPattern(key, init), !1, !1);
            if (!match(":")) return node.finishProperty("init", key, !1, key, !1, !0);
        } else key = parseObjectPropertyKey();
        return expect(":"), init = parsePatternWithDefault(), node.finishProperty("init", key, computed, init, !1, !1);
    }
    function parseObjectPattern() {
        var node = new Node(), properties = [];
        for (expect("{"); !match("}"); ) properties.push(parsePropertyPattern()), match("}") || expect(",");
        return lex(), node.finishObjectPattern(properties);
    }
    function parsePattern() {
        return lookahead.type === Token.Identifier ? parseVariableIdentifier() : match("[") ? parseArrayPattern() : match("{") ? parseObjectPattern() : void throwUnexpectedToken(lookahead);
    }
    function parsePatternWithDefault() {
        var pattern, right, startToken = lookahead;
        return pattern = parsePattern(), match("=") && (lex(), right = isolateCoverGrammar(parseAssignmentExpression), 
        pattern = new WrappingNode(startToken).finishAssignmentPattern(pattern, right)), 
        pattern;
    }
    function parseArrayInitialiser() {
        var restSpread, elements = [], node = new Node();
        for (expect("["); !match("]"); ) match(",") ? (lex(), elements.push(null)) : match("...") ? (restSpread = new Node(), 
        lex(), restSpread.finishSpreadElement(inheritCoverGrammar(parseAssignmentExpression)), 
        match("]") || (isAssignmentTarget = isBindingElement = !1, expect(",")), elements.push(restSpread)) : (elements.push(inheritCoverGrammar(parseAssignmentExpression)), 
        match("]") || expect(","));
        return lex(), node.finishArrayExpression(elements);
    }
    function parsePropertyFunction(node, paramInfo) {
        var previousStrict, body;
        return isAssignmentTarget = isBindingElement = !1, previousStrict = strict, body = isolateCoverGrammar(parseFunctionSourceElements), 
        strict && paramInfo.firstRestricted && tolerateUnexpectedToken(paramInfo.firstRestricted, paramInfo.message), 
        strict && paramInfo.stricted && tolerateUnexpectedToken(paramInfo.stricted, paramInfo.message), 
        strict = previousStrict, node.finishFunctionExpression(null, paramInfo.params, paramInfo.defaults, body);
    }
    function parsePropertyMethodFunction() {
        var params, node = new Node();
        return params = parseParams(), parsePropertyFunction(node, params);
    }
    function parseObjectPropertyKey() {
        var token, expr, node = new Node();
        switch (token = lex(), token.type) {
          case Token.StringLiteral:
          case Token.NumericLiteral:
            return strict && token.octal && tolerateUnexpectedToken(token, Messages.StrictOctalLiteral), 
            node.finishLiteral(token);

          case Token.Identifier:
          case Token.BooleanLiteral:
          case Token.NullLiteral:
          case Token.Keyword:
            return node.finishIdentifier(token.value);

          case Token.Punctuator:
            if ("[" === token.value) return expr = isolateCoverGrammar(parseAssignmentExpression), 
            expect("]"), expr;
        }
        throwUnexpectedToken(token);
    }
    function lookaheadPropertyName() {
        switch (lookahead.type) {
          case Token.Identifier:
          case Token.StringLiteral:
          case Token.BooleanLiteral:
          case Token.NullLiteral:
          case Token.NumericLiteral:
          case Token.Keyword:
            return !0;

          case Token.Punctuator:
            return "[" === lookahead.value;
        }
        return !1;
    }
    function tryParseMethodDefinition(token, key, computed, node) {
        var value, options, methodNode;
        if (token.type === Token.Identifier) {
            if ("get" === token.value && lookaheadPropertyName()) return computed = match("["), 
            key = parseObjectPropertyKey(), methodNode = new Node(), expect("("), expect(")"), 
            value = parsePropertyFunction(methodNode, {
                params: [],
                defaults: [],
                stricted: null,
                firstRestricted: null,
                message: null
            }), node.finishProperty("get", key, computed, value, !1, !1);
            if ("set" === token.value && lookaheadPropertyName()) return computed = match("["), 
            key = parseObjectPropertyKey(), methodNode = new Node(), expect("("), options = {
                params: [],
                defaultCount: 0,
                defaults: [],
                firstRestricted: null,
                paramSet: {}
            }, match(")") ? tolerateUnexpectedToken(lookahead) : (parseParam(options), 0 === options.defaultCount && (options.defaults = [])), 
            expect(")"), value = parsePropertyFunction(methodNode, options), node.finishProperty("set", key, computed, value, !1, !1);
        }
        return match("(") ? (value = parsePropertyMethodFunction(), node.finishProperty("init", key, computed, value, !0, !1)) : null;
    }
    function checkProto(key, computed, hasProto) {
        !1 === computed && (key.type === Syntax.Identifier && "__proto__" === key.name || key.type === Syntax.Literal && "__proto__" === key.value) && (hasProto.value ? tolerateError(Messages.DuplicateProtoProperty) : hasProto.value = !0);
    }
    function parseObjectProperty(hasProto) {
        var computed, key, maybeMethod, value, token = lookahead, node = new Node();
        return computed = match("["), key = parseObjectPropertyKey(), (maybeMethod = tryParseMethodDefinition(token, key, computed, node)) ? (checkProto(maybeMethod.key, maybeMethod.computed, hasProto), 
        maybeMethod) : (checkProto(key, computed, hasProto), match(":") ? (lex(), value = inheritCoverGrammar(parseAssignmentExpression), 
        node.finishProperty("init", key, computed, value, !1, !1)) : token.type === Token.Identifier ? match("=") ? (firstCoverInitializedNameError = lookahead, 
        lex(), value = isolateCoverGrammar(parseAssignmentExpression), node.finishProperty("init", key, computed, new WrappingNode(token).finishAssignmentPattern(key, value), !1, !0)) : node.finishProperty("init", key, computed, key, !1, !0) : void throwUnexpectedToken(lookahead));
    }
    function parseObjectInitialiser() {
        var properties = [], hasProto = {
            value: !1
        }, node = new Node();
        for (expect("{"); !match("}"); ) properties.push(parseObjectProperty(hasProto)), 
        match("}") || expectCommaSeparator();
        return expect("}"), node.finishObjectExpression(properties);
    }
    function reinterpretExpressionAsPattern(expr) {
        var i;
        switch (expr.type) {
          case Syntax.Identifier:
          case Syntax.MemberExpression:
          case Syntax.RestElement:
          case Syntax.AssignmentPattern:
            break;

          case Syntax.SpreadElement:
            expr.type = Syntax.RestElement, reinterpretExpressionAsPattern(expr.argument);
            break;

          case Syntax.ArrayExpression:
            for (expr.type = Syntax.ArrayPattern, i = 0; i < expr.elements.length; i++) null !== expr.elements[i] && reinterpretExpressionAsPattern(expr.elements[i]);
            break;

          case Syntax.ObjectExpression:
            for (expr.type = Syntax.ObjectPattern, i = 0; i < expr.properties.length; i++) reinterpretExpressionAsPattern(expr.properties[i].value);
            break;

          case Syntax.AssignmentExpression:
            expr.type = Syntax.AssignmentPattern, reinterpretExpressionAsPattern(expr.left);
        }
    }
    function parseTemplateElement(option) {
        var node, token;
        return (lookahead.type !== Token.Template || option.head && !lookahead.head) && throwUnexpectedToken(), 
        node = new Node(), token = lex(), node.finishTemplateElement({
            raw: token.value.raw,
            cooked: token.value.cooked
        }, token.tail);
    }
    function parseTemplateLiteral() {
        var quasi, quasis, expressions, node = new Node();
        for (quasi = parseTemplateElement({
            head: !0
        }), quasis = [ quasi ], expressions = []; !quasi.tail; ) expressions.push(parseExpression()), 
        quasi = parseTemplateElement({
            head: !1
        }), quasis.push(quasi);
        return node.finishTemplateLiteral(quasis, expressions);
    }
    function parseGroupExpression() {
        var expr, expressions, startToken, i;
        if (expect("("), match(")")) return lex(), match("=>") || expect("=>"), {
            type: PlaceHolders.ArrowParameterPlaceHolder,
            params: []
        };
        if (startToken = lookahead, match("...")) return expr = parseRestElement(), expect(")"), 
        match("=>") || expect("=>"), {
            type: PlaceHolders.ArrowParameterPlaceHolder,
            params: [ expr ]
        };
        if (isBindingElement = !0, expr = inheritCoverGrammar(parseAssignmentExpression), 
        match(",")) {
            for (isAssignmentTarget = !1, expressions = [ expr ]; startIndex < length && match(","); ) {
                if (lex(), match("...")) {
                    for (isBindingElement || throwUnexpectedToken(lookahead), expressions.push(parseRestElement()), 
                    expect(")"), match("=>") || expect("=>"), isBindingElement = !1, i = 0; i < expressions.length; i++) reinterpretExpressionAsPattern(expressions[i]);
                    return {
                        type: PlaceHolders.ArrowParameterPlaceHolder,
                        params: expressions
                    };
                }
                expressions.push(inheritCoverGrammar(parseAssignmentExpression));
            }
            expr = new WrappingNode(startToken).finishSequenceExpression(expressions);
        }
        if (expect(")"), match("=>")) {
            if (isBindingElement || throwUnexpectedToken(lookahead), expr.type === Syntax.SequenceExpression) for (i = 0; i < expr.expressions.length; i++) reinterpretExpressionAsPattern(expr.expressions[i]); else reinterpretExpressionAsPattern(expr);
            expr = {
                type: PlaceHolders.ArrowParameterPlaceHolder,
                params: expr.type === Syntax.SequenceExpression ? expr.expressions : [ expr ]
            };
        }
        return isBindingElement = !1, expr;
    }
    function parsePrimaryExpression() {
        var type, token, expr, node;
        if (match("(")) return isBindingElement = !1, inheritCoverGrammar(parseGroupExpression);
        if (match("[")) return inheritCoverGrammar(parseArrayInitialiser);
        if (match("{")) return inheritCoverGrammar(parseObjectInitialiser);
        if (type = lookahead.type, node = new Node(), type === Token.Identifier) expr = node.finishIdentifier(lex().value); else if (type === Token.StringLiteral || type === Token.NumericLiteral) isAssignmentTarget = isBindingElement = !1, 
        strict && lookahead.octal && tolerateUnexpectedToken(lookahead, Messages.StrictOctalLiteral), 
        expr = node.finishLiteral(lex()); else if (type === Token.Keyword) {
            if (isAssignmentTarget = isBindingElement = !1, matchKeyword("function")) return parseFunctionExpression();
            if (matchKeyword("this")) return lex(), node.finishThisExpression();
            if (matchKeyword("class")) return parseClassExpression();
            throwUnexpectedToken(lex());
        } else type === Token.BooleanLiteral ? (isAssignmentTarget = isBindingElement = !1, 
        token = lex(), token.value = "true" === token.value, expr = node.finishLiteral(token)) : type === Token.NullLiteral ? (isAssignmentTarget = isBindingElement = !1, 
        token = lex(), token.value = null, expr = node.finishLiteral(token)) : match("/") || match("/=") ? (isAssignmentTarget = isBindingElement = !1, 
        index = startIndex, token = void 0 !== extra.tokens ? collectRegex() : scanRegExp(), 
        lex(), expr = node.finishLiteral(token)) : type === Token.Template ? expr = parseTemplateLiteral() : throwUnexpectedToken(lex());
        return expr;
    }
    function parseArguments() {
        var args = [];
        if (expect("("), !match(")")) for (;startIndex < length && (args.push(isolateCoverGrammar(parseAssignmentExpression)), 
        !match(")")); ) expectCommaSeparator();
        return expect(")"), args;
    }
    function parseNonComputedProperty() {
        var token, node = new Node();
        return token = lex(), isIdentifierName(token) || throwUnexpectedToken(token), node.finishIdentifier(token.value);
    }
    function parseNonComputedMember() {
        return expect("."), parseNonComputedProperty();
    }
    function parseComputedMember() {
        var expr;
        return expect("["), expr = isolateCoverGrammar(parseExpression), expect("]"), expr;
    }
    function parseNewExpression() {
        var callee, args, node = new Node();
        return expectKeyword("new"), callee = isolateCoverGrammar(parseLeftHandSideExpression), 
        args = match("(") ? parseArguments() : [], isAssignmentTarget = isBindingElement = !1, 
        node.finishNewExpression(callee, args);
    }
    function parseLeftHandSideExpressionAllowCall() {
        var quasi, expr, args, property, startToken, previousAllowIn = state.allowIn;
        for (startToken = lookahead, state.allowIn = !0, matchKeyword("super") && state.inFunctionBody ? (expr = new Node(), 
        lex(), expr = expr.finishSuper(), match("(") || match(".") || match("[") || throwUnexpectedToken(lookahead)) : expr = inheritCoverGrammar(matchKeyword("new") ? parseNewExpression : parsePrimaryExpression); ;) if (match(".")) isBindingElement = !1, 
        isAssignmentTarget = !0, property = parseNonComputedMember(), expr = new WrappingNode(startToken).finishMemberExpression(".", expr, property); else if (match("(")) isBindingElement = !1, 
        isAssignmentTarget = !1, args = parseArguments(), expr = new WrappingNode(startToken).finishCallExpression(expr, args); else if (match("[")) isBindingElement = !1, 
        isAssignmentTarget = !0, property = parseComputedMember(), expr = new WrappingNode(startToken).finishMemberExpression("[", expr, property); else {
            if (lookahead.type !== Token.Template || !lookahead.head) break;
            quasi = parseTemplateLiteral(), expr = new WrappingNode(startToken).finishTaggedTemplateExpression(expr, quasi);
        }
        return state.allowIn = previousAllowIn, expr;
    }
    function parseLeftHandSideExpression() {
        var quasi, expr, property, startToken;
        for (assert(state.allowIn, "callee of new expression always allow in keyword."), 
        startToken = lookahead, matchKeyword("super") && state.inFunctionBody ? (expr = new Node(), 
        lex(), expr = expr.finishSuper(), match("[") || match(".") || throwUnexpectedToken(lookahead)) : expr = inheritCoverGrammar(matchKeyword("new") ? parseNewExpression : parsePrimaryExpression); ;) if (match("[")) isBindingElement = !1, 
        isAssignmentTarget = !0, property = parseComputedMember(), expr = new WrappingNode(startToken).finishMemberExpression("[", expr, property); else if (match(".")) isBindingElement = !1, 
        isAssignmentTarget = !0, property = parseNonComputedMember(), expr = new WrappingNode(startToken).finishMemberExpression(".", expr, property); else {
            if (lookahead.type !== Token.Template || !lookahead.head) break;
            quasi = parseTemplateLiteral(), expr = new WrappingNode(startToken).finishTaggedTemplateExpression(expr, quasi);
        }
        return expr;
    }
    function parsePostfixExpression() {
        var expr, token, startToken = lookahead;
        return expr = inheritCoverGrammar(parseLeftHandSideExpressionAllowCall), hasLineTerminator || lookahead.type !== Token.Punctuator || (match("++") || match("--")) && (strict && expr.type === Syntax.Identifier && isRestrictedWord(expr.name) && tolerateError(Messages.StrictLHSPostfix), 
        isAssignmentTarget || tolerateError(Messages.InvalidLHSInAssignment), isAssignmentTarget = isBindingElement = !1, 
        token = lex(), expr = new WrappingNode(startToken).finishPostfixExpression(token.value, expr)), 
        expr;
    }
    function parseUnaryExpression() {
        var token, expr, startToken;
        if (lookahead.type !== Token.Punctuator && lookahead.type !== Token.Keyword) expr = parsePostfixExpression(); else if (match("++") || match("--")) startToken = lookahead, 
        token = lex(), expr = inheritCoverGrammar(parseUnaryExpression), strict && expr.type === Syntax.Identifier && isRestrictedWord(expr.name) && tolerateError(Messages.StrictLHSPrefix), 
        isAssignmentTarget || tolerateError(Messages.InvalidLHSInAssignment), expr = new WrappingNode(startToken).finishUnaryExpression(token.value, expr), 
        isAssignmentTarget = isBindingElement = !1; else if (match("+") || match("-") || match("~") || match("!")) {
            startToken = lookahead, token = lex(), expr = inheritCoverGrammar(parseUnaryExpression);
            var isTemplate = !1;
            if (1 == extra.templateObjects) {
                var operator = token.value;
                "-" == operator && "Literal" == expr.type && (isTemplate = !0);
            }
            0 == isTemplate && (expr = new WrappingNode(startToken).finishUnaryExpression(token.value, expr));
        } else matchKeyword("delete") || matchKeyword("void") || matchKeyword("typeof") ? (startToken = lookahead, 
        token = lex(), expr = inheritCoverGrammar(parseUnaryExpression), expr = new WrappingNode(startToken).finishUnaryExpression(token.value, expr), 
        strict && "delete" === expr.operator && expr.argument.type === Syntax.Identifier && tolerateError(Messages.StrictDelete), 
        isAssignmentTarget = isBindingElement = !1) : expr = parsePostfixExpression();
        return expr;
    }
    function binaryPrecedence(token, allowIn) {
        var prec = 0;
        if (token.type !== Token.Punctuator && token.type !== Token.Keyword) return 0;
        switch (token.value) {
          case "||":
            prec = 1;
            break;

          case "&&":
            prec = 2;
            break;

          case "|":
            prec = 3;
            break;

          case "^":
            prec = 4;
            break;

          case "&":
            prec = 5;
            break;

          case "==":
          case "!=":
          case "===":
          case "!==":
            prec = 6;
            break;

          case "<":
          case ">":
          case "<=":
          case ">=":
          case "instanceof":
            prec = 7;
            break;

          case "in":
            prec = allowIn ? 7 : 0;
            break;

          case "<<":
          case ">>":
          case ">>>":
            prec = 8;
            break;

          case "+":
          case "-":
            prec = 9;
            break;

          case "*":
          case "/":
          case "%":
            prec = 11;
        }
        return prec;
    }
    function parseBinaryExpression() {
        var marker, markers, expr, token, prec, stack, right, operator, left, i;
        if (marker = lookahead, left = inheritCoverGrammar(parseUnaryExpression), token = lookahead, 
        0 === (prec = binaryPrecedence(token, state.allowIn))) return left;
        for (isAssignmentTarget = isBindingElement = !1, token.prec = prec, lex(), markers = [ marker, lookahead ], 
        right = isolateCoverGrammar(parseUnaryExpression), stack = [ left, token, right ]; (prec = binaryPrecedence(lookahead, state.allowIn)) > 0; ) {
            for (;stack.length > 2 && prec <= stack[stack.length - 2].prec; ) right = stack.pop(), 
            operator = stack.pop().value, left = stack.pop(), markers.pop(), expr = new WrappingNode(markers[markers.length - 1]).finishBinaryExpression(operator, left, right), 
            stack.push(expr);
            token = lex(), token.prec = prec, stack.push(token), markers.push(lookahead), expr = isolateCoverGrammar(parseUnaryExpression), 
            stack.push(expr);
        }
        for (i = stack.length - 1, expr = stack[i], markers.pop(); i > 1; ) expr = new WrappingNode(markers.pop()).finishBinaryExpression(stack[i - 1].value, stack[i - 2], expr), 
        i -= 2;
        return expr;
    }
    function parseConditionalExpression() {
        var expr, previousAllowIn, consequent, alternate, startToken;
        return startToken = lookahead, expr = inheritCoverGrammar(parseBinaryExpression), 
        match("?") && (lex(), previousAllowIn = state.allowIn, state.allowIn = !0, consequent = isolateCoverGrammar(parseAssignmentExpression), 
        state.allowIn = previousAllowIn, expect(":"), alternate = isolateCoverGrammar(parseAssignmentExpression), 
        expr = new WrappingNode(startToken).finishConditionalExpression(expr, consequent, alternate), 
        isAssignmentTarget = isBindingElement = !1), expr;
    }
    function parseConciseBody() {
        return match("{") ? parseFunctionSourceElements() : isolateCoverGrammar(parseAssignmentExpression);
    }
    function checkPatternParam(options, param) {
        var i;
        switch (param.type) {
          case Syntax.Identifier:
            validateParam(options, param, param.name);
            break;

          case Syntax.RestElement:
            checkPatternParam(options, param.argument);
            break;

          case Syntax.AssignmentPattern:
            checkPatternParam(options, param.left);
            break;

          case Syntax.ArrayPattern:
            for (i = 0; i < param.elements.length; i++) null !== param.elements[i] && checkPatternParam(options, param.elements[i]);
            break;

          default:
            for (assert(param.type === Syntax.ObjectPattern, "Invalid type"), i = 0; i < param.properties.length; i++) checkPatternParam(options, param.properties[i].value);
        }
    }
    function reinterpretAsCoverFormalsList(expr) {
        var i, len, param, params, defaults, defaultCount, options, token;
        switch (defaults = [], defaultCount = 0, params = [ expr ], expr.type) {
          case Syntax.Identifier:
            break;

          case PlaceHolders.ArrowParameterPlaceHolder:
            params = expr.params;
            break;

          default:
            return null;
        }
        for (options = {
            paramSet: {}
        }, i = 0, len = params.length; i < len; i += 1) switch (param = params[i], param.type) {
          case Syntax.AssignmentPattern:
            params[i] = param.left, defaults.push(param.right), ++defaultCount, checkPatternParam(options, param.left);
            break;

          default:
            checkPatternParam(options, param), params[i] = param, defaults.push(null);
        }
        return options.message === Messages.StrictParamDupe && (token = strict ? options.stricted : options.firstRestricted, 
        throwUnexpectedToken(token, options.message)), 0 === defaultCount && (defaults = []), 
        {
            params: params,
            defaults: defaults,
            stricted: options.stricted,
            firstRestricted: options.firstRestricted,
            message: options.message
        };
    }
    function parseArrowFunctionExpression(options, node) {
        var previousStrict, body;
        return hasLineTerminator && tolerateUnexpectedToken(lookahead), expect("=>"), previousStrict = strict, 
        body = parseConciseBody(), strict && options.firstRestricted && throwUnexpectedToken(options.firstRestricted, options.message), 
        strict && options.stricted && tolerateUnexpectedToken(options.stricted, options.message), 
        strict = previousStrict, node.finishArrowFunctionExpression(options.params, options.defaults, body, body.type !== Syntax.BlockStatement);
    }
    function parseAssignmentExpression() {
        var token, expr, right, list, startToken;
        return startToken = lookahead, token = lookahead, expr = parseConditionalExpression(), 
        expr.type === PlaceHolders.ArrowParameterPlaceHolder || match("=>") ? (isAssignmentTarget = isBindingElement = !1, 
        list = reinterpretAsCoverFormalsList(expr), list ? (firstCoverInitializedNameError = null, 
        parseArrowFunctionExpression(list, new WrappingNode(startToken))) : expr) : (matchAssign() && (isAssignmentTarget || tolerateError(Messages.InvalidLHSInAssignment), 
        strict && expr.type === Syntax.Identifier && isRestrictedWord(expr.name) && tolerateUnexpectedToken(token, Messages.StrictLHSAssignment), 
        match("=") ? reinterpretExpressionAsPattern(expr) : isAssignmentTarget = isBindingElement = !1, 
        token = lex(), right = isolateCoverGrammar(parseAssignmentExpression), expr = new WrappingNode(startToken).finishAssignmentExpression(token.value, expr, right), 
        firstCoverInitializedNameError = null), expr);
    }
    function parseExpression() {
        var expr, expressions, startToken = lookahead;
        if (expr = isolateCoverGrammar(parseAssignmentExpression), match(",")) {
            for (expressions = [ expr ]; startIndex < length && match(","); ) lex(), expressions.push(isolateCoverGrammar(parseAssignmentExpression));
            expr = new WrappingNode(startToken).finishSequenceExpression(expressions);
        }
        return expr;
    }
    function parseStatementListItem() {
        if (lookahead.type === Token.Keyword) switch (lookahead.value) {
          case "export":
            return "module" !== sourceType && tolerateUnexpectedToken(lookahead, Messages.IllegalExportDeclaration), 
            parseExportDeclaration();

          case "import":
            return "module" !== sourceType && tolerateUnexpectedToken(lookahead, Messages.IllegalImportDeclaration), 
            parseImportDeclaration();

          case "const":
          case "let":
            return parseLexicalDeclaration({
                inFor: !1
            });

          case "function":
            return parseFunctionDeclaration(new Node());

          case "class":
            return parseClassDeclaration();
        }
        return parseStatement();
    }
    function parseStatementList() {
        for (var list = []; startIndex < length && !match("}"); ) list.push(parseStatementListItem());
        return list;
    }
    function parseBlock() {
        var block, node = new Node();
        return expect("{"), block = parseStatementList(), expect("}"), node.finishBlockStatement(block);
    }
    function parseVariableIdentifier() {
        var token, node = new Node();
        return token = lex(), token.type !== Token.Identifier && (strict && token.type === Token.Keyword && isStrictModeReservedWord(token.value) ? tolerateUnexpectedToken(token, Messages.StrictReservedWord) : throwUnexpectedToken(token)), 
        node.finishIdentifier(token.value);
    }
    function parseVariableDeclaration() {
        var id, init = null, node = new Node();
        return id = parsePattern(), strict && isRestrictedWord(id.name) && tolerateError(Messages.StrictVarName), 
        match("=") ? (lex(), init = isolateCoverGrammar(parseAssignmentExpression)) : id.type !== Syntax.Identifier && expect("="), 
        node.finishVariableDeclarator(id, init);
    }
    function parseVariableDeclarationList() {
        var list = [];
        do {
            if (list.push(parseVariableDeclaration()), !match(",")) break;
            lex();
        } while (startIndex < length);
        return list;
    }
    function parseVariableStatement(node) {
        var declarations;
        return expectKeyword("var"), declarations = parseVariableDeclarationList(), consumeSemicolon(), 
        node.finishVariableDeclaration(declarations);
    }
    function parseLexicalBinding(kind, options) {
        var id, init = null, node = new Node();
        return id = parsePattern(), strict && id.type === Syntax.Identifier && isRestrictedWord(id.name) && tolerateError(Messages.StrictVarName), 
        "const" === kind ? matchKeyword("in") || (expect("="), init = isolateCoverGrammar(parseAssignmentExpression)) : (!options.inFor && id.type !== Syntax.Identifier || match("=")) && (expect("="), 
        init = isolateCoverGrammar(parseAssignmentExpression)), node.finishVariableDeclarator(id, init);
    }
    function parseBindingList(kind, options) {
        var list = [];
        do {
            if (list.push(parseLexicalBinding(kind, options)), !match(",")) break;
            lex();
        } while (startIndex < length);
        return list;
    }
    function parseLexicalDeclaration(options) {
        var kind, declarations, node = new Node();
        return kind = lex().value, assert("let" === kind || "const" === kind, "Lexical declaration must be either let or const"), 
        declarations = parseBindingList(kind, options), consumeSemicolon(), node.finishLexicalDeclaration(declarations, kind);
    }
    function parseRestElement() {
        var param, node = new Node();
        return lex(), match("{") && throwError(Messages.ObjectPatternAsRestParameter), param = parseVariableIdentifier(), 
        match("=") && throwError(Messages.DefaultRestParameter), match(")") || throwError(Messages.ParameterAfterRestParameter), 
        node.finishRestElement(param);
    }
    function parseEmptyStatement(node) {
        return expect(";"), node.finishEmptyStatement();
    }
    function parseExpressionStatement(node) {
        var expr = parseExpression();
        return consumeSemicolon(), node.finishExpressionStatement(expr);
    }
    function parseIfStatement(node) {
        var test, consequent, alternate;
        return expectKeyword("if"), expect("("), test = parseExpression(), expect(")"), 
        consequent = parseStatement(), matchKeyword("else") ? (lex(), alternate = parseStatement()) : alternate = null, 
        node.finishIfStatement(test, consequent, alternate);
    }
    function parseDoWhileStatement(node) {
        var body, test, oldInIteration;
        return expectKeyword("do"), oldInIteration = state.inIteration, state.inIteration = !0, 
        body = parseStatement(), state.inIteration = oldInIteration, expectKeyword("while"), 
        expect("("), test = parseExpression(), expect(")"), match(";") && lex(), node.finishDoWhileStatement(body, test);
    }
    function parseWhileStatement(node) {
        var test, body, oldInIteration;
        return expectKeyword("while"), expect("("), test = parseExpression(), expect(")"), 
        oldInIteration = state.inIteration, state.inIteration = !0, body = parseStatement(), 
        state.inIteration = oldInIteration, node.finishWhileStatement(test, body);
    }
    function parseForStatement(node) {
        var init, initSeq, initStartToken, test, update, left, right, kind, declarations, body, oldInIteration, previousAllowIn = state.allowIn;
        if (init = test = update = null, expectKeyword("for"), expect("("), match(";")) lex(); else if (matchKeyword("var")) init = new Node(), 
        lex(), state.allowIn = !1, init = init.finishVariableDeclaration(parseVariableDeclarationList()), 
        state.allowIn = previousAllowIn, 1 === init.declarations.length && matchKeyword("in") ? (lex(), 
        left = init, right = parseExpression(), init = null) : expect(";"); else if (matchKeyword("const") || matchKeyword("let")) init = new Node(), 
        kind = lex().value, state.allowIn = !1, declarations = parseBindingList(kind, {
            inFor: !0
        }), state.allowIn = previousAllowIn, 1 === declarations.length && null === declarations[0].init && matchKeyword("in") ? (init = init.finishLexicalDeclaration(declarations, kind), 
        lex(), left = init, right = parseExpression(), init = null) : (consumeSemicolon(), 
        init = init.finishLexicalDeclaration(declarations, kind)); else if (initStartToken = lookahead, 
        state.allowIn = !1, init = inheritCoverGrammar(parseAssignmentExpression), state.allowIn = previousAllowIn, 
        matchKeyword("in")) isAssignmentTarget || tolerateError(Messages.InvalidLHSInForIn), 
        lex(), reinterpretExpressionAsPattern(init), left = init, right = parseExpression(), 
        init = null; else {
            if (match(",")) {
                for (initSeq = [ init ]; match(","); ) lex(), initSeq.push(isolateCoverGrammar(parseAssignmentExpression));
                init = new WrappingNode(initStartToken).finishSequenceExpression(initSeq);
            }
            expect(";");
        }
        return void 0 === left && (match(";") || (test = parseExpression()), expect(";"), 
        match(")") || (update = parseExpression())), expect(")"), oldInIteration = state.inIteration, 
        state.inIteration = !0, body = isolateCoverGrammar(parseStatement), state.inIteration = oldInIteration, 
        void 0 === left ? node.finishForStatement(init, test, update, body) : node.finishForInStatement(left, right, body);
    }
    function parseContinueStatement(node) {
        var key, label = null;
        return expectKeyword("continue"), 59 === source.charCodeAt(startIndex) ? (lex(), 
        state.inIteration || throwError(Messages.IllegalContinue), node.finishContinueStatement(null)) : hasLineTerminator ? (state.inIteration || throwError(Messages.IllegalContinue), 
        node.finishContinueStatement(null)) : (lookahead.type === Token.Identifier && (label = parseVariableIdentifier(), 
        key = "$" + label.name, Object.prototype.hasOwnProperty.call(state.labelSet, key) || throwError(Messages.UnknownLabel, label.name)), 
        consumeSemicolon(), null !== label || state.inIteration || throwError(Messages.IllegalContinue), 
        node.finishContinueStatement(label));
    }
    function parseBreakStatement(node) {
        var key, label = null;
        return expectKeyword("break"), 59 === source.charCodeAt(lastIndex) ? (lex(), state.inIteration || state.inSwitch || throwError(Messages.IllegalBreak), 
        node.finishBreakStatement(null)) : hasLineTerminator ? (state.inIteration || state.inSwitch || throwError(Messages.IllegalBreak), 
        node.finishBreakStatement(null)) : (lookahead.type === Token.Identifier && (label = parseVariableIdentifier(), 
        key = "$" + label.name, Object.prototype.hasOwnProperty.call(state.labelSet, key) || throwError(Messages.UnknownLabel, label.name)), 
        consumeSemicolon(), null !== label || state.inIteration || state.inSwitch || throwError(Messages.IllegalBreak), 
        node.finishBreakStatement(label));
    }
    function parseReturnStatement(node) {
        var argument = null;
        return expectKeyword("return"), state.inFunctionBody || tolerateError(Messages.IllegalReturn), 
        32 === source.charCodeAt(lastIndex) && isIdentifierStart(source.charCodeAt(lastIndex + 1)) ? (argument = parseExpression(), 
        consumeSemicolon(), node.finishReturnStatement(argument)) : hasLineTerminator ? node.finishReturnStatement(null) : (match(";") || match("}") || lookahead.type === Token.EOF || (argument = parseExpression()), 
        consumeSemicolon(), node.finishReturnStatement(argument));
    }
    function parseWithStatement(node) {
        var object, body;
        return strict && tolerateError(Messages.StrictModeWith), expectKeyword("with"), 
        expect("("), object = parseExpression(), expect(")"), body = parseStatement(), node.finishWithStatement(object, body);
    }
    function parseSwitchCase() {
        var test, statement, consequent = [], node = new Node();
        for (matchKeyword("default") ? (lex(), test = null) : (expectKeyword("case"), test = parseExpression()), 
        expect(":"); startIndex < length && !(match("}") || matchKeyword("default") || matchKeyword("case")); ) statement = parseStatementListItem(), 
        consequent.push(statement);
        return node.finishSwitchCase(test, consequent);
    }
    function parseSwitchStatement(node) {
        var discriminant, cases, clause, oldInSwitch, defaultFound;
        if (expectKeyword("switch"), expect("("), discriminant = parseExpression(), expect(")"), 
        expect("{"), cases = [], match("}")) return lex(), node.finishSwitchStatement(discriminant, cases);
        for (oldInSwitch = state.inSwitch, state.inSwitch = !0, defaultFound = !1; startIndex < length && !match("}"); ) clause = parseSwitchCase(), 
        null === clause.test && (defaultFound && throwError(Messages.MultipleDefaultsInSwitch), 
        defaultFound = !0), cases.push(clause);
        return state.inSwitch = oldInSwitch, expect("}"), node.finishSwitchStatement(discriminant, cases);
    }
    function parseThrowStatement(node) {
        var argument;
        return expectKeyword("throw"), hasLineTerminator && throwError(Messages.NewlineAfterThrow), 
        argument = parseExpression(), consumeSemicolon(), node.finishThrowStatement(argument);
    }
    function parseCatchClause() {
        var param, body, node = new Node();
        return expectKeyword("catch"), expect("("), match(")") && throwUnexpectedToken(lookahead), 
        param = parsePattern(), strict && isRestrictedWord(param.name) && tolerateError(Messages.StrictCatchVariable), 
        expect(")"), body = parseBlock(), node.finishCatchClause(param, body);
    }
    function parseTryStatement(node) {
        var block, handler = null, finalizer = null;
        return expectKeyword("try"), block = parseBlock(), matchKeyword("catch") && (handler = parseCatchClause()), 
        matchKeyword("finally") && (lex(), finalizer = parseBlock()), handler || finalizer || throwError(Messages.NoCatchOrFinally), 
        node.finishTryStatement(block, handler, finalizer);
    }
    function parseDebuggerStatement(node) {
        return expectKeyword("debugger"), consumeSemicolon(), node.finishDebuggerStatement();
    }
    function parseStatement() {
        var expr, labeledBody, key, node, type = lookahead.type;
        if (type === Token.EOF && throwUnexpectedToken(lookahead), type === Token.Punctuator && "{" === lookahead.value) return parseBlock();
        if (isAssignmentTarget = isBindingElement = !0, node = new Node(), type === Token.Punctuator) switch (lookahead.value) {
          case ";":
            return parseEmptyStatement(node);

          case "(":
            return parseExpressionStatement(node);
        } else if (type === Token.Keyword) switch (lookahead.value) {
          case "break":
            return parseBreakStatement(node);

          case "continue":
            return parseContinueStatement(node);

          case "debugger":
            return parseDebuggerStatement(node);

          case "do":
            return parseDoWhileStatement(node);

          case "for":
            return parseForStatement(node);

          case "function":
            return parseFunctionDeclaration(node);

          case "if":
            return parseIfStatement(node);

          case "return":
            return parseReturnStatement(node);

          case "switch":
            return parseSwitchStatement(node);

          case "throw":
            return parseThrowStatement(node);

          case "try":
            return parseTryStatement(node);

          case "var":
            return parseVariableStatement(node);

          case "while":
            return parseWhileStatement(node);

          case "with":
            return parseWithStatement(node);
        }
        return expr = parseExpression(), expr.type === Syntax.Identifier && match(":") ? (lex(), 
        key = "$" + expr.name, Object.prototype.hasOwnProperty.call(state.labelSet, key) && throwError(Messages.Redeclaration, "Label", expr.name), 
        state.labelSet[key] = !0, labeledBody = parseStatement(), delete state.labelSet[key], 
        node.finishLabeledStatement(expr, labeledBody)) : (consumeSemicolon(), node.finishExpressionStatement(expr));
    }
    function parseFunctionSourceElements() {
        var statement, token, directive, firstRestricted, oldLabelSet, oldInIteration, oldInSwitch, oldInFunctionBody, oldParenthesisCount, body = [], node = new Node();
        for (expect("{"); startIndex < length && lookahead.type === Token.StringLiteral && (token = lookahead, 
        statement = parseStatementListItem(), body.push(statement), statement.expression.type === Syntax.Literal); ) directive = source.slice(token.start + 1, token.end - 1), 
        "use strict" === directive ? (strict = !0, firstRestricted && tolerateUnexpectedToken(firstRestricted, Messages.StrictOctalLiteral)) : !firstRestricted && token.octal && (firstRestricted = token);
        for (oldLabelSet = state.labelSet, oldInIteration = state.inIteration, oldInSwitch = state.inSwitch, 
        oldInFunctionBody = state.inFunctionBody, oldParenthesisCount = state.parenthesizedCount, 
        state.labelSet = {}, state.inIteration = !1, state.inSwitch = !1, state.inFunctionBody = !0, 
        state.parenthesizedCount = 0; startIndex < length && !match("}"); ) body.push(parseStatementListItem());
        return expect("}"), state.labelSet = oldLabelSet, state.inIteration = oldInIteration, 
        state.inSwitch = oldInSwitch, state.inFunctionBody = oldInFunctionBody, state.parenthesizedCount = oldParenthesisCount, 
        node.finishBlockStatement(body);
    }
    function validateParam(options, param, name) {
        var key = "$" + name;
        strict ? (isRestrictedWord(name) && (options.stricted = param, options.message = Messages.StrictParamName), 
        Object.prototype.hasOwnProperty.call(options.paramSet, key) && (options.stricted = param, 
        options.message = Messages.StrictParamDupe)) : options.firstRestricted || (isRestrictedWord(name) ? (options.firstRestricted = param, 
        options.message = Messages.StrictParamName) : isStrictModeReservedWord(name) ? (options.firstRestricted = param, 
        options.message = Messages.StrictReservedWord) : Object.prototype.hasOwnProperty.call(options.paramSet, key) && (options.firstRestricted = param, 
        options.message = Messages.StrictParamDupe)), options.paramSet[key] = !0;
    }
    function parseParam(options) {
        var token, param, def;
        return token = lookahead, "..." === token.value ? (param = parseRestElement(), validateParam(options, param.argument, param.argument.name), 
        options.params.push(param), options.defaults.push(null), !1) : (param = parsePatternWithDefault(), 
        validateParam(options, token, token.value), param.type === Syntax.AssignmentPattern && (def = param.right, 
        param = param.left, ++options.defaultCount), options.params.push(param), options.defaults.push(def), 
        !match(")"));
    }
    function parseParams(firstRestricted) {
        var options;
        if (options = {
            params: [],
            defaultCount: 0,
            defaults: [],
            firstRestricted: firstRestricted
        }, expect("("), !match(")")) for (options.paramSet = {}; startIndex < length && parseParam(options); ) expect(",");
        return expect(")"), 0 === options.defaultCount && (options.defaults = []), {
            params: options.params,
            defaults: options.defaults,
            stricted: options.stricted,
            firstRestricted: options.firstRestricted,
            message: options.message
        };
    }
    function parseFunctionDeclaration(node, identifierIsOptional) {
        var body, token, stricted, tmp, firstRestricted, message, previousStrict, id = null, params = [], defaults = [];
        return expectKeyword("function"), identifierIsOptional && match("(") || (token = lookahead, 
        id = parseVariableIdentifier(), strict ? isRestrictedWord(token.value) && tolerateUnexpectedToken(token, Messages.StrictFunctionName) : isRestrictedWord(token.value) ? (firstRestricted = token, 
        message = Messages.StrictFunctionName) : isStrictModeReservedWord(token.value) && (firstRestricted = token, 
        message = Messages.StrictReservedWord)), tmp = parseParams(firstRestricted), params = tmp.params, 
        defaults = tmp.defaults, stricted = tmp.stricted, firstRestricted = tmp.firstRestricted, 
        tmp.message && (message = tmp.message), previousStrict = strict, body = parseFunctionSourceElements(), 
        strict && firstRestricted && throwUnexpectedToken(firstRestricted, message), strict && stricted && tolerateUnexpectedToken(stricted, message), 
        strict = previousStrict, node.finishFunctionDeclaration(id, params, defaults, body);
    }
    function parseFunctionExpression() {
        var token, stricted, firstRestricted, message, tmp, body, previousStrict, id = null, params = [], defaults = [], node = new Node();
        return expectKeyword("function"), match("(") || (token = lookahead, id = parseVariableIdentifier(), 
        strict ? isRestrictedWord(token.value) && tolerateUnexpectedToken(token, Messages.StrictFunctionName) : isRestrictedWord(token.value) ? (firstRestricted = token, 
        message = Messages.StrictFunctionName) : isStrictModeReservedWord(token.value) && (firstRestricted = token, 
        message = Messages.StrictReservedWord)), tmp = parseParams(firstRestricted), params = tmp.params, 
        defaults = tmp.defaults, stricted = tmp.stricted, firstRestricted = tmp.firstRestricted, 
        tmp.message && (message = tmp.message), previousStrict = strict, body = parseFunctionSourceElements(), 
        strict && firstRestricted && throwUnexpectedToken(firstRestricted, message), strict && stricted && tolerateUnexpectedToken(stricted, message), 
        strict = previousStrict, node.finishFunctionExpression(id, params, defaults, body);
    }
    function parseClassBody() {
        var classBody, token, isStatic, body, method, computed, key, hasConstructor = !1;
        for (classBody = new Node(), expect("{"), body = []; !match("}"); ) match(";") ? lex() : (method = new Node(), 
        token = lookahead, isStatic = !1, computed = match("["), key = parseObjectPropertyKey(), 
        "static" === key.name && lookaheadPropertyName() && (token = lookahead, isStatic = !0, 
        computed = match("["), key = parseObjectPropertyKey()), method = tryParseMethodDefinition(token, key, computed, method), 
        method ? (method.static = isStatic, "init" === method.kind && (method.kind = "method"), 
        isStatic ? method.computed || "prototype" !== (method.key.name || method.key.value.toString()) || throwUnexpectedToken(token, Messages.StaticPrototype) : method.computed || "constructor" !== (method.key.name || method.key.value.toString()) || ("method" === method.kind && method.method && !method.value.generator || throwUnexpectedToken(token, Messages.ConstructorSpecialMethod), 
        hasConstructor ? throwUnexpectedToken(token, Messages.DuplicateConstructor) : hasConstructor = !0, 
        method.kind = "constructor"), method.type = Syntax.MethodDefinition, delete method.method, 
        delete method.shorthand, body.push(method)) : throwUnexpectedToken(lookahead));
        return lex(), classBody.finishClassBody(body);
    }
    function parseClassDeclaration(identifierIsOptional) {
        var classBody, id = null, superClass = null, classNode = new Node(), previousStrict = strict;
        return strict = !0, expectKeyword("class"), identifierIsOptional && lookahead.type !== Token.Identifier || (id = parseVariableIdentifier()), 
        matchKeyword("extends") && (lex(), superClass = isolateCoverGrammar(parseLeftHandSideExpressionAllowCall)), 
        classBody = parseClassBody(), strict = previousStrict, classNode.finishClassDeclaration(id, superClass, classBody);
    }
    function parseClassExpression() {
        var classBody, id = null, superClass = null, classNode = new Node(), previousStrict = strict;
        return strict = !0, expectKeyword("class"), lookahead.type === Token.Identifier && (id = parseVariableIdentifier()), 
        matchKeyword("extends") && (lex(), superClass = isolateCoverGrammar(parseLeftHandSideExpressionAllowCall)), 
        classBody = parseClassBody(), strict = previousStrict, classNode.finishClassExpression(id, superClass, classBody);
    }
    function parseModuleSpecifier() {
        var node = new Node();
        return lookahead.type !== Token.StringLiteral && throwError(Messages.InvalidModuleSpecifier), 
        node.finishLiteral(lex());
    }
    function parseExportSpecifier() {
        var exported, local, def, node = new Node();
        return matchKeyword("default") ? (def = new Node(), lex(), local = def.finishIdentifier("default")) : local = parseVariableIdentifier(), 
        matchContextualKeyword("as") && (lex(), exported = parseNonComputedProperty()), 
        node.finishExportSpecifier(local, exported);
    }
    function parseExportNamedDeclaration(node) {
        var isExportFromIdentifier, declaration = null, src = null, specifiers = [];
        if (lookahead.type === Token.Keyword) switch (lookahead.value) {
          case "let":
          case "const":
          case "var":
          case "class":
          case "function":
            return declaration = parseStatementListItem(), node.finishExportNamedDeclaration(declaration, specifiers, null);
        }
        if (expect("{"), !match("}")) do {
            isExportFromIdentifier = isExportFromIdentifier || matchKeyword("default"), specifiers.push(parseExportSpecifier());
        } while (match(",") && lex());
        return expect("}"), matchContextualKeyword("from") ? (lex(), src = parseModuleSpecifier(), 
        consumeSemicolon()) : isExportFromIdentifier ? throwError(lookahead.value ? Messages.UnexpectedToken : Messages.MissingFromClause, lookahead.value) : consumeSemicolon(), 
        node.finishExportNamedDeclaration(declaration, specifiers, src);
    }
    function parseExportDefaultDeclaration(node) {
        var declaration = null, expression = null;
        return expectKeyword("default"), matchKeyword("function") ? (declaration = parseFunctionDeclaration(new Node(), !0), 
        node.finishExportDefaultDeclaration(declaration)) : matchKeyword("class") ? (declaration = parseClassDeclaration(!0), 
        node.finishExportDefaultDeclaration(declaration)) : (matchContextualKeyword("from") && throwError(Messages.UnexpectedToken, lookahead.value), 
        expression = match("{") ? parseObjectInitialiser() : match("[") ? parseArrayInitialiser() : parseAssignmentExpression(), 
        consumeSemicolon(), node.finishExportDefaultDeclaration(expression));
    }
    function parseExportAllDeclaration(node) {
        var src;
        return expect("*"), matchContextualKeyword("from") || throwError(lookahead.value ? Messages.UnexpectedToken : Messages.MissingFromClause, lookahead.value), 
        lex(), src = parseModuleSpecifier(), consumeSemicolon(), node.finishExportAllDeclaration(src);
    }
    function parseExportDeclaration() {
        var node = new Node();
        return state.inFunctionBody && throwError(Messages.IllegalExportDeclaration), expectKeyword("export"), 
        matchKeyword("default") ? parseExportDefaultDeclaration(node) : match("*") ? parseExportAllDeclaration(node) : parseExportNamedDeclaration(node);
    }
    function parseImportSpecifier() {
        var local, imported, node = new Node();
        return imported = parseNonComputedProperty(), matchContextualKeyword("as") && (lex(), 
        local = parseVariableIdentifier()), node.finishImportSpecifier(local, imported);
    }
    function parseNamedImports() {
        var specifiers = [];
        if (expect("{"), !match("}")) do {
            specifiers.push(parseImportSpecifier());
        } while (match(",") && lex());
        return expect("}"), specifiers;
    }
    function parseImportDefaultSpecifier() {
        var local, node = new Node();
        return local = parseNonComputedProperty(), node.finishImportDefaultSpecifier(local);
    }
    function parseImportNamespaceSpecifier() {
        var local, node = new Node();
        return expect("*"), matchContextualKeyword("as") || throwError(Messages.NoAsAfterImportNamespace), 
        lex(), local = parseNonComputedProperty(), node.finishImportNamespaceSpecifier(local);
    }
    function parseImportDeclaration() {
        var specifiers, src, node = new Node();
        return state.inFunctionBody && throwError(Messages.IllegalImportDeclaration), expectKeyword("import"), 
        specifiers = [], lookahead.type === Token.StringLiteral ? (src = parseModuleSpecifier(), 
        consumeSemicolon(), node.finishImportDeclaration(specifiers, src)) : (!matchKeyword("default") && isIdentifierName(lookahead) && (specifiers.push(parseImportDefaultSpecifier()), 
        match(",") && lex()), match("*") ? specifiers.push(parseImportNamespaceSpecifier()) : match("{") && (specifiers = specifiers.concat(parseNamedImports())), 
        matchContextualKeyword("from") || throwError(lookahead.value ? Messages.UnexpectedToken : Messages.MissingFromClause, lookahead.value), 
        lex(), src = parseModuleSpecifier(), consumeSemicolon(), node.finishImportDeclaration(specifiers, src));
    }
    function parseScriptBody() {
        for (var statement, token, directive, firstRestricted, body = []; startIndex < length && (token = lookahead, 
        token.type === Token.StringLiteral) && (statement = parseStatementListItem(), body.push(statement), 
        statement.expression.type === Syntax.Literal); ) directive = source.slice(token.start + 1, token.end - 1), 
        "use strict" === directive ? (strict = !0, firstRestricted && tolerateUnexpectedToken(firstRestricted, Messages.StrictOctalLiteral)) : !firstRestricted && token.octal && (firstRestricted = token);
        for (;startIndex < length && void 0 !== (statement = parseStatementListItem()); ) body.push(statement);
        return body;
    }
    function parseProgram() {
        var body, node;
        return peek(), node = new Node(), body = parseScriptBody(), node.finishProgram(body);
    }
    function filterTokenLocation() {
        var i, entry, token, tokens = [];
        for (i = 0; i < extra.tokens.length; ++i) entry = extra.tokens[i], token = {
            type: entry.type,
            value: entry.value
        }, entry.regex && (token.regex = {
            pattern: entry.regex.pattern,
            flags: entry.regex.flags
        }), extra.range && (token.range = entry.range), extra.loc && (token.loc = entry.loc), 
        tokens.push(token);
        extra.tokens = tokens;
    }
    function tokenize(code, options) {
        var toString, tokens;
        toString = String, "string" == typeof code || code instanceof String || (code = toString(code)), 
        source = code, index = 0, lineNumber = source.length > 0 ? 1 : 0, lineStart = 0, 
        startIndex = index, startLineNumber = lineNumber, startLineStart = lineStart, length = source.length, 
        lookahead = null, state = {
            allowIn: !0,
            labelSet: {},
            inFunctionBody: !1,
            inIteration: !1,
            inSwitch: !1,
            lastCommentStart: -1,
            curlyStack: []
        }, extra = {}, options = options || {}, options.tokens = !0, extra.tokens = [], 
        extra.tokenize = !0, extra.openParenToken = -1, extra.openCurlyToken = -1, extra.range = "boolean" == typeof options.range && options.range, 
        extra.loc = "boolean" == typeof options.loc && options.loc, "boolean" == typeof options.comment && options.comment && (extra.comments = []), 
        "boolean" == typeof options.tolerant && options.tolerant && (extra.errors = []);
        try {
            if (peek(), lookahead.type === Token.EOF) return extra.tokens;
            for (lex(); lookahead.type !== Token.EOF; ) try {
                lex();
            } catch (lexError) {
                if (extra.errors) {
                    recordError(lexError);
                    break;
                }
                throw lexError;
            }
            filterTokenLocation(), tokens = extra.tokens, void 0 !== extra.comments && (tokens.comments = extra.comments), 
            void 0 !== extra.errors && (tokens.errors = extra.errors);
        } catch (e) {
            throw e;
        } finally {
            extra = {};
        }
        return tokens;
    }
    function parse(code, options) {
        var program, toString;
        if (toString = String, "string" == typeof code || code instanceof String || (code = toString(code)), 
        source = code, index = 0, lineNumber = source.length > 0 ? 1 : 0, lineStart = 0, 
        startIndex = index, startLineNumber = lineNumber, startLineStart = lineStart, length = source.length, 
        lookahead = null, state = {
            allowIn: !0,
            labelSet: {},
            inFunctionBody: !1,
            inIteration: !1,
            inSwitch: !1,
            lastCommentStart: -1,
            curlyStack: []
        }, sourceType = "script", strict = !1, extra = {}, void 0 !== options && (extra.range = "boolean" == typeof options.range && options.range, 
        extra.loc = "boolean" == typeof options.loc && options.loc, extra.attachComment = "boolean" == typeof options.attachComment && options.attachComment, 
        extra.loc && null !== options.source && void 0 !== options.source && (extra.source = toString(options.source)), 
        "boolean" == typeof options.tokens && options.tokens && (extra.tokens = []), "boolean" == typeof options.comment && options.comment && (extra.comments = []), 
        "boolean" == typeof options.tolerant && options.tolerant && (extra.errors = []), 
        extra.attachComment && (extra.range = !0, extra.comments = [], extra.bottomRightStack = [], 
        extra.trailingComments = [], extra.leadingComments = []), "boolean" == typeof options.templateAll && options.templateAll && (extra.templateLiterals = !0, 
        extra.templateArrays = !0, extra.templateObjects = !0), "boolean" == typeof options.templateLiterals && options.templateLiterals && (extra.templateLiterals = !0), 
        "boolean" == typeof options.templateArrays && options.templateArrays && (extra.templateArrays = !0), 
        "boolean" == typeof options.templateObjects && options.templateObjects && (extra.templateObjects = !0), 
        void 0 !== options.methodsToCount)) {
            extra.methodCounts = {};
            for (var i = 0; i < options.methodsToCount.length; i++) extra.methodCounts[options.methodsToCount[i]] = 0;
        }
        try {
            program = parseProgram(), void 0 !== extra.comments && (program.comments = extra.comments), 
            void 0 !== extra.tokens && (filterTokenLocation(), program.tokens = extra.tokens), 
            void 0 !== extra.errors && (program.errors = extra.errors), void 0 !== extra.methodCounts && (program.methodCounts = extra.methodCounts);
        } catch (e) {
            throw e;
        } finally {
            extra = {};
        }
        return program;
    }
    var Token, TokenName, FnExprTokens, Syntax, PlaceHolders, Messages, Regex, source, strict, sourceType, index, lineNumber, lineStart, hasLineTerminator, lastIndex, lastLineNumber, lastLineStart, startIndex, startLineNumber, startLineStart, scanning, length, lookahead, state, extra, isBindingElement, isAssignmentTarget, firstCoverInitializedNameError, exports = {};
    return Token = {
        BooleanLiteral: 1,
        EOF: 2,
        Identifier: 3,
        Keyword: 4,
        NullLiteral: 5,
        NumericLiteral: 6,
        Punctuator: 7,
        StringLiteral: 8,
        RegularExpression: 9,
        Template: 10
    }, TokenName = {}, TokenName[Token.BooleanLiteral] = "Boolean", TokenName[Token.EOF] = "<end>", 
    TokenName[Token.Identifier] = "Identifier", TokenName[Token.Keyword] = "Keyword", 
    TokenName[Token.NullLiteral] = "Null", TokenName[Token.NumericLiteral] = "Numeric", 
    TokenName[Token.Punctuator] = "Punctuator", TokenName[Token.StringLiteral] = "String", 
    TokenName[Token.RegularExpression] = "RegularExpression", TokenName[Token.Template] = "Template", 
    FnExprTokens = [ "(", "{", "[", "in", "typeof", "instanceof", "new", "return", "case", "delete", "throw", "void", "=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", ",", "+", "-", "*", "/", "%", "++", "--", "<<", ">>", ">>>", "&", "|", "^", "!", "~", "&&", "||", "?", ":", "===", "==", ">=", "<=", "<", ">", "!=", "!==" ], 
    Syntax = {
        AssignmentExpression: "AssignmentExpression",
        AssignmentPattern: "AssignmentPattern",
        ArrayExpression: "ArrayExpression",
        ArrayPattern: "ArrayPattern",
        ArrowFunctionExpression: "ArrowFunctionExpression",
        BlockStatement: "BlockStatement",
        BinaryExpression: "BinaryExpression",
        BreakStatement: "BreakStatement",
        CallExpression: "CallExpression",
        CatchClause: "CatchClause",
        ClassBody: "ClassBody",
        ClassDeclaration: "ClassDeclaration",
        ClassExpression: "ClassExpression",
        ConditionalExpression: "ConditionalExpression",
        ContinueStatement: "ContinueStatement",
        DoWhileStatement: "DoWhileStatement",
        DebuggerStatement: "DebuggerStatement",
        EmptyStatement: "EmptyStatement",
        ExportAllDeclaration: "ExportAllDeclaration",
        ExportDefaultDeclaration: "ExportDefaultDeclaration",
        ExportNamedDeclaration: "ExportNamedDeclaration",
        ExportSpecifier: "ExportSpecifier",
        ExpressionStatement: "ExpressionStatement",
        ForStatement: "ForStatement",
        ForInStatement: "ForInStatement",
        FunctionDeclaration: "FunctionDeclaration",
        FunctionExpression: "FunctionExpression",
        Identifier: "Identifier",
        IfStatement: "IfStatement",
        ImportDeclaration: "ImportDeclaration",
        ImportDefaultSpecifier: "ImportDefaultSpecifier",
        ImportNamespaceSpecifier: "ImportNamespaceSpecifier",
        ImportSpecifier: "ImportSpecifier",
        Literal: "Literal",
        LabeledStatement: "LabeledStatement",
        LogicalExpression: "LogicalExpression",
        MemberExpression: "MemberExpression",
        MethodDefinition: "MethodDefinition",
        NewExpression: "NewExpression",
        ObjectExpression: "ObjectExpression",
        ObjectPattern: "ObjectPattern",
        Program: "Program",
        Property: "Property",
        RestElement: "RestElement",
        ReturnStatement: "ReturnStatement",
        SequenceExpression: "SequenceExpression",
        SpreadElement: "SpreadElement",
        Super: "Super",
        SwitchCase: "SwitchCase",
        SwitchStatement: "SwitchStatement",
        TaggedTemplateExpression: "TaggedTemplateExpression",
        TemplateElement: "TemplateElement",
        TemplateLiteral: "TemplateLiteral",
        ThisExpression: "ThisExpression",
        ThrowStatement: "ThrowStatement",
        TryStatement: "TryStatement",
        UnaryExpression: "UnaryExpression",
        UpdateExpression: "UpdateExpression",
        VariableDeclaration: "VariableDeclaration",
        VariableDeclarator: "VariableDeclarator",
        WhileStatement: "WhileStatement",
        WithStatement: "WithStatement"
    }, PlaceHolders = {
        ArrowParameterPlaceHolder: "ArrowParameterPlaceHolder"
    }, Messages = {
        UnexpectedToken: "Unexpected token %0",
        UnexpectedNumber: "Unexpected number",
        UnexpectedString: "Unexpected string",
        UnexpectedIdentifier: "Unexpected identifier",
        UnexpectedReserved: "Unexpected reserved word",
        UnexpectedTemplate: "Unexpected quasi %0",
        UnexpectedEOS: "Unexpected end of input",
        NewlineAfterThrow: "Illegal newline after throw",
        InvalidRegExp: "Invalid regular expression",
        UnterminatedRegExp: "Invalid regular expression: missing /",
        InvalidLHSInAssignment: "Invalid left-hand side in assignment",
        InvalidLHSInForIn: "Invalid left-hand side in for-in",
        MultipleDefaultsInSwitch: "More than one default clause in switch statement",
        NoCatchOrFinally: "Missing catch or finally after try",
        UnknownLabel: "Undefined label '%0'",
        Redeclaration: "%0 '%1' has already been declared",
        IllegalContinue: "Illegal continue statement",
        IllegalBreak: "Illegal break statement",
        IllegalReturn: "Illegal return statement",
        StrictModeWith: "Strict mode code may not include a with statement",
        StrictCatchVariable: "Catch variable may not be eval or arguments in strict mode",
        StrictVarName: "Variable name may not be eval or arguments in strict mode",
        StrictParamName: "Parameter name eval or arguments is not allowed in strict mode",
        StrictParamDupe: "Strict mode function may not have duplicate parameter names",
        StrictFunctionName: "Function name may not be eval or arguments in strict mode",
        StrictOctalLiteral: "Octal literals are not allowed in strict mode.",
        StrictDelete: "Delete of an unqualified identifier in strict mode.",
        StrictLHSAssignment: "Assignment to eval or arguments is not allowed in strict mode",
        StrictLHSPostfix: "Postfix increment/decrement may not have eval or arguments operand in strict mode",
        StrictLHSPrefix: "Prefix increment/decrement may not have eval or arguments operand in strict mode",
        StrictReservedWord: "Use of future reserved word in strict mode",
        TemplateOctalLiteral: "Octal literals are not allowed in template strings.",
        ParameterAfterRestParameter: "Rest parameter must be last formal parameter",
        DefaultRestParameter: "Unexpected token =",
        ObjectPatternAsRestParameter: "Unexpected token {",
        DuplicateProtoProperty: "Duplicate __proto__ fields are not allowed in object literals",
        ConstructorSpecialMethod: "Class constructor may not be an accessor",
        DuplicateConstructor: "A class may only have one constructor",
        StaticPrototype: "Classes may not have static property named prototype",
        MissingFromClause: "Unexpected token",
        NoAsAfterImportNamespace: "Unexpected token",
        InvalidModuleSpecifier: "Unexpected token",
        IllegalImportDeclaration: "Unexpected token",
        IllegalExportDeclaration: "Unexpected token"
    }, Regex = {
        NonAsciiIdentifierStart: new RegExp("[\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376\u0377\u037a-\u037d\u037f\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u052f\u0531-\u0556\u0559\u0561-\u0587\u05d0-\u05ea\u05f0-\u05f2\u0620-\u064a\u066e\u066f\u0671-\u06d3\u06d5\u06e5\u06e6\u06ee\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u08a0-\u08b2\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0980\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc\u09dd\u09df-\u09e1\u09f0\u09f1\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0\u0ae1\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3d\u0b5c\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d\u0c58\u0c59\u0c60\u0c61\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cde\u0ce0\u0ce1\u0cf1\u0cf2\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d60\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32\u0e33\u0e40-\u0e46\u0e81\u0e82\u0e84\u0e87\u0e88\u0e8a\u0e8d\u0e94-\u0e97\u0e99-\u0e9f\u0ea1-\u0ea3\u0ea5\u0ea7\u0eaa\u0eab\u0ead-\u0eb0\u0eb2\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f4\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1877\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191e\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19c1-\u19c7\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4b\u1b83-\u1ba0\u1bae\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1ce9-\u1cec\u1cee-\u1cf1\u1cf5\u1cf6\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cee\u2cf2\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2e2f\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312d\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fcc\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a\ua62b\ua640-\ua66e\ua67f-\ua69d\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua78e\ua790-\ua7ad\ua7b0\ua7b1\ua7f7-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\ua9e0-\ua9e4\ua9e6-\ua9ef\ua9fa-\ua9fe\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa7e-\uaaaf\uaab1\uaab5\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab5f\uab64\uab65\uabc0-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]"),
        NonAsciiIdentifierPart: new RegExp("[\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0300-\u0374\u0376\u0377\u037a-\u037d\u037f\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u0483-\u0487\u048a-\u052f\u0531-\u0556\u0559\u0561-\u0587\u0591-\u05bd\u05bf\u05c1\u05c2\u05c4\u05c5\u05c7\u05d0-\u05ea\u05f0-\u05f2\u0610-\u061a\u0620-\u0669\u066e-\u06d3\u06d5-\u06dc\u06df-\u06e8\u06ea-\u06fc\u06ff\u0710-\u074a\u074d-\u07b1\u07c0-\u07f5\u07fa\u0800-\u082d\u0840-\u085b\u08a0-\u08b2\u08e4-\u0963\u0966-\u096f\u0971-\u0983\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bc-\u09c4\u09c7\u09c8\u09cb-\u09ce\u09d7\u09dc\u09dd\u09df-\u09e3\u09e6-\u09f1\u0a01-\u0a03\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a3c\u0a3e-\u0a42\u0a47\u0a48\u0a4b-\u0a4d\u0a51\u0a59-\u0a5c\u0a5e\u0a66-\u0a75\u0a81-\u0a83\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abc-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ad0\u0ae0-\u0ae3\u0ae6-\u0aef\u0b01-\u0b03\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3c-\u0b44\u0b47\u0b48\u0b4b-\u0b4d\u0b56\u0b57\u0b5c\u0b5d\u0b5f-\u0b63\u0b66-\u0b6f\u0b71\u0b82\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd0\u0bd7\u0be6-\u0bef\u0c00-\u0c03\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55\u0c56\u0c58\u0c59\u0c60-\u0c63\u0c66-\u0c6f\u0c81-\u0c83\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbc-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5\u0cd6\u0cde\u0ce0-\u0ce3\u0ce6-\u0cef\u0cf1\u0cf2\u0d01-\u0d03\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d-\u0d44\u0d46-\u0d48\u0d4a-\u0d4e\u0d57\u0d60-\u0d63\u0d66-\u0d6f\u0d7a-\u0d7f\u0d82\u0d83\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0de6-\u0def\u0df2\u0df3\u0e01-\u0e3a\u0e40-\u0e4e\u0e50-\u0e59\u0e81\u0e82\u0e84\u0e87\u0e88\u0e8a\u0e8d\u0e94-\u0e97\u0e99-\u0e9f\u0ea1-\u0ea3\u0ea5\u0ea7\u0eaa\u0eab\u0ead-\u0eb9\u0ebb-\u0ebd\u0ec0-\u0ec4\u0ec6\u0ec8-\u0ecd\u0ed0-\u0ed9\u0edc-\u0edf\u0f00\u0f18\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e-\u0f47\u0f49-\u0f6c\u0f71-\u0f84\u0f86-\u0f97\u0f99-\u0fbc\u0fc6\u1000-\u1049\u1050-\u109d\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u135d-\u135f\u1380-\u138f\u13a0-\u13f4\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1714\u1720-\u1734\u1740-\u1753\u1760-\u176c\u176e-\u1770\u1772\u1773\u1780-\u17d3\u17d7\u17dc\u17dd\u17e0-\u17e9\u180b-\u180d\u1810-\u1819\u1820-\u1877\u1880-\u18aa\u18b0-\u18f5\u1900-\u191e\u1920-\u192b\u1930-\u193b\u1946-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u19d0-\u19d9\u1a00-\u1a1b\u1a20-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1aa7\u1ab0-\u1abd\u1b00-\u1b4b\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1bf3\u1c00-\u1c37\u1c40-\u1c49\u1c4d-\u1c7d\u1cd0-\u1cd2\u1cd4-\u1cf6\u1cf8\u1cf9\u1d00-\u1df5\u1dfc-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u200c\u200d\u203f\u2040\u2054\u2071\u207f\u2090-\u209c\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d7f-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2de0-\u2dff\u2e2f\u3005-\u3007\u3021-\u302f\u3031-\u3035\u3038-\u303c\u3041-\u3096\u3099\u309a\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312d\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fcc\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua62b\ua640-\ua66f\ua674-\ua67d\ua67f-\ua69d\ua69f-\ua6f1\ua717-\ua71f\ua722-\ua788\ua78b-\ua78e\ua790-\ua7ad\ua7b0\ua7b1\ua7f7-\ua827\ua840-\ua873\ua880-\ua8c4\ua8d0-\ua8d9\ua8e0-\ua8f7\ua8fb\ua900-\ua92d\ua930-\ua953\ua960-\ua97c\ua980-\ua9c0\ua9cf-\ua9d9\ua9e0-\ua9fe\uaa00-\uaa36\uaa40-\uaa4d\uaa50-\uaa59\uaa60-\uaa76\uaa7a-\uaac2\uaadb-\uaadd\uaae0-\uaaef\uaaf2-\uaaf6\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab5f\uab64\uab65\uabc0-\uabea\uabec\uabed\uabf0-\uabf9\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe00-\ufe0f\ufe20-\ufe2d\ufe33\ufe34\ufe4d-\ufe4f\ufe70-\ufe74\ufe76-\ufefc\uff10-\uff19\uff21-\uff3a\uff3f\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]")
    }, WrappingNode.prototype = Node.prototype = {
        processComment: function() {
            var lastChild, leadingComments, trailingComments, i, comment, bottomRight = extra.bottomRightStack, last = bottomRight[bottomRight.length - 1];
            if (!(this.type === Syntax.Program && this.body.length > 0)) {
                if (extra.trailingComments.length > 0) {
                    for (trailingComments = [], i = extra.trailingComments.length - 1; i >= 0; --i) comment = extra.trailingComments[i], 
                    comment.range[0] >= this.range[1] && (trailingComments.unshift(comment), extra.trailingComments.splice(i, 1));
                    extra.trailingComments = [];
                } else last && last.trailingComments && last.trailingComments[0].range[0] >= this.range[1] && (trailingComments = last.trailingComments, 
                delete last.trailingComments);
                if (last) for (;last && last.range[0] >= this.range[0]; ) lastChild = last, last = bottomRight.pop();
                if (lastChild) lastChild.leadingComments && lastChild.leadingComments[lastChild.leadingComments.length - 1].range[1] <= this.range[0] && (this.leadingComments = lastChild.leadingComments, 
                lastChild.leadingComments = void 0); else if (extra.leadingComments.length > 0) for (leadingComments = [], 
                i = extra.leadingComments.length - 1; i >= 0; --i) comment = extra.leadingComments[i], 
                comment.range[1] <= this.range[0] && (leadingComments.unshift(comment), extra.leadingComments.splice(i, 1));
                leadingComments && leadingComments.length > 0 && (this.leadingComments = leadingComments), 
                trailingComments && trailingComments.length > 0 && (this.trailingComments = trailingComments), 
                bottomRight.push(this);
            }
        },
        finish: function() {
            extra.range && (this.range[1] = lastIndex), extra.loc && (this.loc.end = {
                line: lastLineNumber,
                column: lastIndex - lastLineStart
            }, extra.source && (this.loc.source = extra.source)), extra.attachComment && this.processComment();
        },
        finishArrayExpression: function(elements) {
            if (this.type = Syntax.ArrayExpression, this.elements = elements, 1 == extra.templateArrays) {
                for (var scrubbedElements = [], templatedNode = null, allTemplate = !0, i = 0; i < elements.length; i++) {
                    var element = elements[i];
                    if (null == element) null == templatedNode && (templatedNode = {
                        type: Syntax.Literal,
                        value: "?",
                        raw: "null",
                        isTemplate: !0
                    }, scrubbedElements.push(templatedNode)); else if (!0 === element.isTemplate) {
                        var elementRaw = void 0 !== element.raw ? element.raw : element.value;
                        null == templatedNode ? (templatedNode = {
                            type: Syntax.Literal,
                            value: "?",
                            raw: elementRaw,
                            isTemplate: !0
                        }, scrubbedElements.push(templatedNode)) : templatedNode.raw += "," + elementRaw;
                    } else null != templatedNode ? (templatedNode = null, scrubbedElements.push(element), 
                    allTemplate = !1) : (scrubbedElements.push(element), allTemplate = !1);
                }
                this.elements = scrubbedElements, this.isTemplate = allTemplate;
            }
            return this.finish(), this;
        },
        finishArrowFunctionExpression: function(params, defaults, body, expression) {
            return this.type = Syntax.ArrowFunctionExpression, this.id = null, this.params = params, 
            this.defaults = defaults, this.body = body, this.generator = !1, this.expression = expression, 
            this.finish(), this;
        },
        finishAssignmentExpression: function(operator, left, right) {
            return this.type = Syntax.AssignmentExpression, this.operator = operator, this.left = left, 
            this.right = right, this.finish(), this;
        },
        finishAssignmentPattern: function(left, right) {
            return this.type = Syntax.AssignmentPattern, this.left = left, this.right = right, 
            this.finish(), this;
        },
        finishBinaryExpression: function(operator, left, right) {
            return this.type = "||" === operator || "&&" === operator ? Syntax.LogicalExpression : Syntax.BinaryExpression, 
            this.operator = operator, this.left = left, this.right = right, this.finish(), this;
        },
        finishBlockStatement: function(body) {
            return this.type = Syntax.BlockStatement, this.body = body, this.finish(), this;
        },
        finishBreakStatement: function(label) {
            return this.type = Syntax.BreakStatement, this.label = label, this.finish(), this;
        },
        finishCallExpression: function(callee, args) {
            if (this.type = Syntax.CallExpression, this.callee = callee, void 0 !== extra.methodCounts) if ("Identifier" === callee.type && void 0 !== extra.methodCounts[callee.name]) extra.methodCounts[callee.name] += 1; else if ("MemberExpression" === callee.type) {
                var key = callee.object.name + "." + callee.property.name;
                void 0 !== extra.methodCounts[key] && (extra.methodCounts[key] += 1);
            }
            return this.arguments = args, this.finish(), this;
        },
        finishCatchClause: function(param, body) {
            return this.type = Syntax.CatchClause, this.param = param, this.body = body, this.finish(), 
            this;
        },
        finishClassBody: function(body) {
            return this.type = Syntax.ClassBody, this.body = body, this.finish(), this;
        },
        finishClassDeclaration: function(id, superClass, body) {
            return this.type = Syntax.ClassDeclaration, this.id = id, this.superClass = superClass, 
            this.body = body, this.finish(), this;
        },
        finishClassExpression: function(id, superClass, body) {
            return this.type = Syntax.ClassExpression, this.id = id, this.superClass = superClass, 
            this.body = body, this.finish(), this;
        },
        finishConditionalExpression: function(test, consequent, alternate) {
            return this.type = Syntax.ConditionalExpression, this.test = test, this.consequent = consequent, 
            this.alternate = alternate, this.finish(), this;
        },
        finishContinueStatement: function(label) {
            return this.type = Syntax.ContinueStatement, this.label = label, this.finish(), 
            this;
        },
        finishDebuggerStatement: function() {
            return this.type = Syntax.DebuggerStatement, this.finish(), this;
        },
        finishDoWhileStatement: function(body, test) {
            return this.type = Syntax.DoWhileStatement, this.body = body, this.test = test, 
            this.finish(), this;
        },
        finishEmptyStatement: function() {
            return this.type = Syntax.EmptyStatement, this.finish(), this;
        },
        finishExpressionStatement: function(expression) {
            return this.type = Syntax.ExpressionStatement, this.expression = expression, this.finish(), 
            this;
        },
        finishForStatement: function(init, test, update, body) {
            return this.type = Syntax.ForStatement, this.init = init, this.test = test, this.update = update, 
            this.body = body, this.finish(), this;
        },
        finishForInStatement: function(left, right, body) {
            return this.type = Syntax.ForInStatement, this.left = left, this.right = right, 
            this.body = body, this.each = !1, this.finish(), this;
        },
        finishFunctionDeclaration: function(id, params, defaults, body) {
            return this.type = Syntax.FunctionDeclaration, this.id = id, this.params = params, 
            this.defaults = defaults, this.body = body, this.generator = !1, this.expression = !1, 
            this.finish(), this;
        },
        finishFunctionExpression: function(id, params, defaults, body) {
            return this.type = Syntax.FunctionExpression, this.id = id, this.params = params, 
            this.defaults = defaults, this.body = body, this.generator = !1, this.expression = !1, 
            this.finish(), this;
        },
        finishIdentifier: function(name) {
            return this.type = Syntax.Identifier, this.name = name, this.finish(), this;
        },
        finishIfStatement: function(test, consequent, alternate) {
            return this.type = Syntax.IfStatement, this.test = test, this.consequent = consequent, 
            this.alternate = alternate, this.finish(), this;
        },
        finishLabeledStatement: function(label, body) {
            return this.type = Syntax.LabeledStatement, this.label = label, this.body = body, 
            this.finish(), this;
        },
        finishLiteral: function(token) {
            return this.type = Syntax.Literal, 1 == extra.templateLiterals ? (this.value = "?", 
            this.isTemplate = !0) : this.value = token.value, this.raw = source.slice(token.start, token.end), 
            token.regex && (this.regex = token.regex), this.finish(), this;
        },
        finishMemberExpression: function(accessor, object, property) {
            return this.type = Syntax.MemberExpression, this.computed = "[" === accessor, this.object = object, 
            this.property = property, this.finish(), this;
        },
        finishNewExpression: function(callee, args) {
            return this.type = Syntax.NewExpression, this.callee = callee, this.arguments = args, 
            this.finish(), this;
        },
        finishObjectExpression: function(properties) {
            if (1 == extra.templateObjects) {
                for (var newProps = [], foundTemplateProperty = !1, allTemplates = !0, i = 0; i < properties.length; i++) {
                    var property = properties[i];
                    if (property.key.type != Syntax.Literal && property.key.type != Syntax.Identifier || !0 !== property.value.isTemplate) allTemplates = !1, 
                    newProps.push(property); else if (!foundTemplateProperty) {
                        if (foundTemplateProperty = !0, property.key.type == Syntax.Identifier) {
                            var newKey = new Node();
                            newKey.type = Syntax.Literal, newKey.raw = property.key.name, newKey.value = "?", 
                            newKey.finish(), property.key = newKey;
                        }
                        if (property.value.type != Syntax.Literal) {
                            var newValue = new Node();
                            newValue.type = Syntax.Literal, newValue.raw = "?", newValue.value = "?", newValue.finish(), 
                            property.value = newValue;
                        }
                        newProps.push(property);
                    }
                }
                properties = newProps, this.isTemplate = allTemplates;
            }
            return this.type = Syntax.ObjectExpression, this.properties = properties, this.finish(), 
            this;
        },
        finishObjectPattern: function(properties) {
            return this.type = Syntax.ObjectPattern, this.properties = properties, this.finish(), 
            this;
        },
        finishPostfixExpression: function(operator, argument) {
            return this.type = Syntax.UpdateExpression, this.operator = operator, this.argument = argument, 
            this.prefix = !1, this.finish(), this;
        },
        finishProgram: function(body) {
            return this.type = Syntax.Program, this.body = body, "module" === sourceType && (this.sourceType = sourceType), 
            this.finish(), this;
        },
        finishProperty: function(kind, key, computed, value, method, shorthand) {
            return this.type = Syntax.Property, this.key = key, this.computed = computed, this.value = value, 
            this.kind = kind, this.method = method, this.shorthand = shorthand, this.finish(), 
            this;
        },
        finishRestElement: function(argument) {
            return this.type = Syntax.RestElement, this.argument = argument, this.finish(), 
            this;
        },
        finishReturnStatement: function(argument) {
            return this.type = Syntax.ReturnStatement, this.argument = argument, this.finish(), 
            this;
        },
        finishSequenceExpression: function(expressions) {
            return this.type = Syntax.SequenceExpression, this.expressions = expressions, this.finish(), 
            this;
        },
        finishSpreadElement: function(argument) {
            return this.type = Syntax.SpreadElement, this.argument = argument, this.finish(), 
            this;
        },
        finishSwitchCase: function(test, consequent) {
            return this.type = Syntax.SwitchCase, this.test = test, this.consequent = consequent, 
            this.finish(), this;
        },
        finishSuper: function() {
            return this.type = Syntax.Super, this.finish(), this;
        },
        finishSwitchStatement: function(discriminant, cases) {
            return this.type = Syntax.SwitchStatement, this.discriminant = discriminant, this.cases = cases, 
            this.finish(), this;
        },
        finishTaggedTemplateExpression: function(tag, quasi) {
            return this.type = Syntax.TaggedTemplateExpression, this.tag = tag, this.quasi = quasi, 
            this.finish(), this;
        },
        finishTemplateElement: function(value, tail) {
            return this.type = Syntax.TemplateElement, this.value = value, this.tail = tail, 
            this.finish(), this;
        },
        finishTemplateLiteral: function(quasis, expressions) {
            return this.type = Syntax.TemplateLiteral, this.quasis = quasis, this.expressions = expressions, 
            this.finish(), this;
        },
        finishThisExpression: function() {
            return this.type = Syntax.ThisExpression, this.finish(), this;
        },
        finishThrowStatement: function(argument) {
            return this.type = Syntax.ThrowStatement, this.argument = argument, this.finish(), 
            this;
        },
        finishTryStatement: function(block, handler, finalizer) {
            return this.type = Syntax.TryStatement, this.block = block, this.guardedHandlers = [], 
            this.handlers = handler ? [ handler ] : [], this.handler = handler, this.finalizer = finalizer, 
            this.finish(), this;
        },
        finishUnaryExpression: function(operator, argument) {
            return this.type = "++" === operator || "--" === operator ? Syntax.UpdateExpression : Syntax.UnaryExpression, 
            this.operator = operator, this.argument = argument, this.prefix = !0, this.finish(), 
            this;
        },
        finishVariableDeclaration: function(declarations) {
            return this.type = Syntax.VariableDeclaration, this.declarations = declarations, 
            this.kind = "var", this.finish(), this;
        },
        finishLexicalDeclaration: function(declarations, kind) {
            return this.type = Syntax.VariableDeclaration, this.declarations = declarations, 
            this.kind = kind, this.finish(), this;
        },
        finishVariableDeclarator: function(id, init) {
            return this.type = Syntax.VariableDeclarator, this.id = id, this.init = init, this.finish(), 
            this;
        },
        finishWhileStatement: function(test, body) {
            return this.type = Syntax.WhileStatement, this.test = test, this.body = body, this.finish(), 
            this;
        },
        finishWithStatement: function(object, body) {
            return this.type = Syntax.WithStatement, this.object = object, this.body = body, 
            this.finish(), this;
        },
        finishExportSpecifier: function(local, exported) {
            return this.type = Syntax.ExportSpecifier, this.exported = exported || local, this.local = local, 
            this.finish(), this;
        },
        finishImportDefaultSpecifier: function(local) {
            return this.type = Syntax.ImportDefaultSpecifier, this.local = local, this.finish(), 
            this;
        },
        finishImportNamespaceSpecifier: function(local) {
            return this.type = Syntax.ImportNamespaceSpecifier, this.local = local, this.finish(), 
            this;
        },
        finishExportNamedDeclaration: function(declaration, specifiers, src) {
            return this.type = Syntax.ExportNamedDeclaration, this.declaration = declaration, 
            this.specifiers = specifiers, this.source = src, this.finish(), this;
        },
        finishExportDefaultDeclaration: function(declaration) {
            return this.type = Syntax.ExportDefaultDeclaration, this.declaration = declaration, 
            this.finish(), this;
        },
        finishExportAllDeclaration: function(src) {
            return this.type = Syntax.ExportAllDeclaration, this.source = src, this.finish(), 
            this;
        },
        finishImportSpecifier: function(local, imported) {
            return this.type = Syntax.ImportSpecifier, this.local = local || imported, this.imported = imported, 
            this.finish(), this;
        },
        finishImportDeclaration: function(specifiers, src) {
            return this.type = Syntax.ImportDeclaration, this.specifiers = specifiers, this.source = src, 
            this.finish(), this;
        }
    }, exports.version = "2.2.0", exports.tokenize = tokenize, exports.parse = parse, 
    exports.Syntax = function() {
        var name, types = {};
        "function" == typeof Object.create && (types = Object.create(null));
        for (name in Syntax) Syntax.hasOwnProperty(name) && (types[name] = Syntax[name]);
        return "function" == typeof Object.freeze && Object.freeze(types), types;
    }(), exports;
}();

!function() {
    var require = function(file, cwd) {
        var resolved = require.resolve(file, cwd || "/"), mod = require.modules[resolved];
        if (!mod) throw new Error("Failed to resolve module " + file + ", tried " + resolved);
        var cached = require.cache[resolved];
        return cached ? cached.exports : mod();
    };
    require.paths = [], require.modules = {}, require.cache = {}, require.extensions = [ ".js", ".coffee", ".json" ], 
    require._core = {
        assert: !0,
        events: !0,
        fs: !0,
        path: !0,
        vm: !0
    }, require.resolve = function() {
        return function(x, cwd) {
            function loadAsFileSync(x) {
                if (x = path.normalize(x), require.modules[x]) return x;
                for (var i = 0; i < require.extensions.length; i++) {
                    var ext = require.extensions[i];
                    if (require.modules[x + ext]) return x + ext;
                }
            }
            function loadAsDirectorySync(x) {
                x = x.replace(/\/+$/, "");
                var pkgfile = path.normalize(x + "/package.json");
                if (require.modules[pkgfile]) {
                    var pkg = require.modules[pkgfile](), b = pkg.browserify;
                    if ("object" == typeof b && b.main) {
                        var m = loadAsFileSync(path.resolve(x, b.main));
                        if (m) return m;
                    } else if ("string" == typeof b) {
                        var m = loadAsFileSync(path.resolve(x, b));
                        if (m) return m;
                    } else if (pkg.main) {
                        var m = loadAsFileSync(path.resolve(x, pkg.main));
                        if (m) return m;
                    }
                }
                return loadAsFileSync(x + "/index");
            }
            function loadNodeModulesSync(x, start) {
                for (var dirs = nodeModulesPathsSync(start), i = 0; i < dirs.length; i++) {
                    var dir = dirs[i], m = loadAsFileSync(dir + "/" + x);
                    if (m) return m;
                    var n = loadAsDirectorySync(dir + "/" + x);
                    if (n) return n;
                }
                var m = loadAsFileSync(x);
                if (m) return m;
            }
            function nodeModulesPathsSync(start) {
                var parts;
                parts = "/" === start ? [ "" ] : path.normalize(start).split("/");
                for (var dirs = [], i = parts.length - 1; i >= 0; i--) if ("node_modules" !== parts[i]) {
                    var dir = parts.slice(0, i + 1).join("/") + "/node_modules";
                    dirs.push(dir);
                }
                return dirs;
            }
            if (cwd || (cwd = "/"), require._core[x]) return x;
            var path = require.modules.path();
            cwd = path.resolve("/", cwd);
            var y = cwd || "/";
            if (x.match(/^(?:\.\.?\/|\/)/)) {
                var m = loadAsFileSync(path.resolve(y, x)) || loadAsDirectorySync(path.resolve(y, x));
                if (m) return m;
            }
            var n = loadNodeModulesSync(x, y);
            if (n) return n;
            throw new Error("Cannot find module '" + x + "'");
        };
    }(), require.alias = function(from, to) {
        var path = require.modules.path(), res = null;
        try {
            res = require.resolve(from + "/package.json", "/");
        } catch (err) {
            res = require.resolve(from, "/");
        }
        for (var basedir = path.dirname(res), keys = (Object.keys || function(obj) {
            var res = [];
            for (var key in obj) res.push(key);
            return res;
        })(require.modules), i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (key.slice(0, basedir.length + 1) === basedir + "/") {
                var f = key.slice(basedir.length);
                require.modules[to + f] = require.modules[basedir + f];
            } else key === basedir && (require.modules[to] = require.modules[basedir]);
        }
    }, function() {
        var process = {}, global = "undefined" != typeof window ? window : {}, definedProcess = !1;
        require.define = function(filename, fn) {
            !definedProcess && require.modules.__browserify_process && (process = require.modules.__browserify_process(), 
            definedProcess = !0);
            var dirname = require._core[filename] ? "" : require.modules.path().dirname(filename), require_ = function(file) {
                var requiredModule = require(file, dirname), cached = require.cache[require.resolve(file, dirname)];
                return cached && null === cached.parent && (cached.parent = module_), requiredModule;
            };
            require_.resolve = function(name) {
                return require.resolve(name, dirname);
            }, require_.modules = require.modules, require_.define = require.define, require_.cache = require.cache;
            var module_ = {
                id: filename,
                filename: filename,
                exports: {},
                loaded: !1,
                parent: null
            };
            require.modules[filename] = function() {
                return require.cache[filename] = module_, fn.call(module_.exports, require_, module_, module_.exports, dirname, filename, process, global), 
                module_.loaded = !0, module_.exports;
            };
        };
    }(), require.define("path", function(require, module, exports, __dirname, __filename, process, global) {
        function filter(xs, fn) {
            for (var res = [], i = 0; i < xs.length; i++) fn(xs[i], i, xs) && res.push(xs[i]);
            return res;
        }
        function normalizeArray(parts, allowAboveRoot) {
            for (var up = 0, i = parts.length; i >= 0; i--) {
                var last = parts[i];
                "." == last ? parts.splice(i, 1) : ".." === last ? (parts.splice(i, 1), up++) : up && (parts.splice(i, 1), 
                up--);
            }
            if (allowAboveRoot) for (;up--; up) parts.unshift("..");
            return parts;
        }
        var splitPathRe = /^(.+\/(?!$)|\/)?((?:.+?)?(\.[^.]*)?)$/;
        exports.resolve = function() {
            for (var resolvedPath = "", resolvedAbsolute = !1, i = arguments.length; i >= -1 && !resolvedAbsolute; i--) {
                var path = i >= 0 ? arguments[i] : process.cwd();
                "string" == typeof path && path && (resolvedPath = path + "/" + resolvedPath, resolvedAbsolute = "/" === path.charAt(0));
            }
            return resolvedPath = normalizeArray(filter(resolvedPath.split("/"), function(p) {
                return !!p;
            }), !resolvedAbsolute).join("/"), (resolvedAbsolute ? "/" : "") + resolvedPath || ".";
        }, exports.normalize = function(path) {
            var isAbsolute = "/" === path.charAt(0), trailingSlash = "/" === path.slice(-1);
            return path = normalizeArray(filter(path.split("/"), function(p) {
                return !!p;
            }), !isAbsolute).join("/"), path || isAbsolute || (path = "."), path && trailingSlash && (path += "/"), 
            (isAbsolute ? "/" : "") + path;
        }, exports.join = function() {
            var paths = Array.prototype.slice.call(arguments, 0);
            return exports.normalize(filter(paths, function(p, index) {
                return p && "string" == typeof p;
            }).join("/"));
        }, exports.dirname = function(path) {
            var dir = splitPathRe.exec(path)[1] || "";
            return dir ? 1 === dir.length ? dir : dir.substring(0, dir.length - 1) : ".";
        }, exports.basename = function(path, ext) {
            var f = splitPathRe.exec(path)[2] || "";
            return ext && f.substr(-1 * ext.length) === ext && (f = f.substr(0, f.length - ext.length)), 
            f;
        }, exports.extname = function(path) {
            return splitPathRe.exec(path)[3] || "";
        }, exports.relative = function(from, to) {
            function trim(arr) {
                for (var start = 0; start < arr.length && "" === arr[start]; start++) ;
                for (var end = arr.length - 1; end >= 0 && "" === arr[end]; end--) ;
                return start > end ? [] : arr.slice(start, end - start + 1);
            }
            from = exports.resolve(from).substr(1), to = exports.resolve(to).substr(1);
            for (var fromParts = trim(from.split("/")), toParts = trim(to.split("/")), length = Math.min(fromParts.length, toParts.length), samePartsLength = length, i = 0; i < length; i++) if (fromParts[i] !== toParts[i]) {
                samePartsLength = i;
                break;
            }
            for (var outputParts = [], i = samePartsLength; i < fromParts.length; i++) outputParts.push("..");
            return outputParts = outputParts.concat(toParts.slice(samePartsLength)), outputParts.join("/");
        };
    }), require.define("__browserify_process", function(require, module, exports, __dirname, __filename, process, global) {
        var process = module.exports = {};
        process.nextTick = function() {
            var canSetImmediate = "undefined" != typeof window && window.setImmediate, canPost = "undefined" != typeof window && window.postMessage && window.addEventListener;
            if (canSetImmediate) return function(f) {
                return window.setImmediate(f);
            };
            if (canPost) {
                var queue = [];
                return window.addEventListener("message", function(ev) {
                    if (ev.source === window && "browserify-tick" === ev.data && (ev.stopPropagation(), 
                    queue.length > 0)) {
                        queue.shift()();
                    }
                }, !0), function(fn) {
                    queue.push(fn), window.postMessage("browserify-tick", "*");
                };
            }
            return function(fn) {
                setTimeout(fn, 0);
            };
        }(), process.title = "browser", process.browser = !0, process.env = {}, process.argv = [], 
        process.binding = function(name) {
            if ("evals" === name) return require("vm");
            throw new Error("No such module. (Possibly not yet loaded)");
        }, function() {
            var path, cwd = "/";
            process.cwd = function() {
                return cwd;
            }, process.chdir = function(dir) {
                path || (path = require("path")), cwd = path.resolve(dir, cwd);
            };
        }();
    }), require.define("/package.json", function(require, module, exports, __dirname, __filename, process, global) {
        module.exports = {
            main: "escodegen.js"
        };
    }), require.define("/escodegen.js", function(require, module, exports, __dirname, __filename, process, global) {
        !function() {
            "use strict";
            function getDefaultOptions() {
                return {
                    indent: null,
                    base: null,
                    parse: null,
                    comment: !1,
                    format: {
                        indent: {
                            style: "    ",
                            base: 0,
                            adjustMultilineComment: !1
                        },
                        json: !1,
                        renumber: !1,
                        hexadecimal: !1,
                        quotes: "single",
                        escapeless: !1,
                        compact: !1,
                        parentheses: !0,
                        semicolons: !0,
                        safeConcatenation: !1
                    },
                    moz: {
                        starlessGenerator: !1,
                        parenthesizedComprehensionBlock: !1
                    },
                    sourceMap: null,
                    sourceMapRoot: null,
                    sourceMapWithCode: !1,
                    directive: !1,
                    verbatim: null
                };
            }
            function stringToArray(str) {
                var i, length = str.length, result = [];
                for (i = 0; i < length; i += 1) result[i] = str.charAt(i);
                return result;
            }
            function stringRepeat(str, num) {
                var result = "";
                for (num |= 0; num > 0; num >>>= 1, str += str) 1 & num && (result += str);
                return result;
            }
            function SourceNodeMock(line, column, filename, chunk) {
                function flatten(input) {
                    var i, iz;
                    if (isArray(input)) for (i = 0, iz = input.length; i < iz; ++i) flatten(input[i]); else input instanceof SourceNodeMock ? result.push(input) : "string" == typeof input && input && result.push(input);
                }
                var result = [];
                flatten(chunk), this.children = result;
            }
            function hasLineTerminator(str) {
                return /[\r\n]/g.test(str);
            }
            function endsWithLineTerminator(str) {
                var ch = str.charAt(str.length - 1);
                return "\r" === ch || "\n" === ch;
            }
            function deepCopy(obj) {
                var key, val, ret = {};
                for (key in obj) obj.hasOwnProperty(key) && (val = obj[key], ret[key] = "object" == typeof val && null !== val ? deepCopy(val) : val);
                return ret;
            }
            function updateDeeply(target, override) {
                function isHashObject(target) {
                    return "object" == typeof target && target instanceof Object && !(target instanceof RegExp);
                }
                var key, val;
                for (key in override) override.hasOwnProperty(key) && (val = override[key], isHashObject(val) ? isHashObject(target[key]) ? updateDeeply(target[key], val) : target[key] = updateDeeply({}, val) : target[key] = val);
                return target;
            }
            function generateNumber(value) {
                var result, point, temp, exponent, pos;
                if (value !== value) throw new Error("Numeric literal whose value is NaN");
                if (value < 0 || 0 === value && 1 / value < 0) throw new Error("Numeric literal whose value is negative");
                if (value === 1 / 0) return json ? "null" : renumber ? "1e400" : "1e+400";
                if (result = "" + value, !renumber || result.length < 3) return result;
                for (point = result.indexOf("."), json || "0" !== result.charAt(0) || 1 !== point || (point = 0, 
                result = result.slice(1)), temp = result, result = result.replace("e+", "e"), exponent = 0, 
                (pos = temp.indexOf("e")) > 0 && (exponent = +temp.slice(pos + 1), temp = temp.slice(0, pos)), 
                point >= 0 && (exponent -= temp.length - point - 1, temp = +(temp.slice(0, point) + temp.slice(point + 1)) + ""), 
                pos = 0; "0" === temp.charAt(temp.length + pos - 1); ) pos -= 1;
                return 0 !== pos && (exponent -= pos, temp = temp.slice(0, pos)), 0 !== exponent && (temp += "e" + exponent), 
                (temp.length < result.length || hexadecimal && value > 1e12 && Math.floor(value) === value && (temp = "0x" + value.toString(16)).length < result.length) && +temp === value && (result = temp), 
                result;
            }
            function escapeAllowedCharacter(ch, next) {
                var code = ch.charCodeAt(0), hex = code.toString(16), result = "\\";
                switch (ch) {
                  case "\b":
                    result += "b";
                    break;

                  case "\f":
                    result += "f";
                    break;

                  case "\t":
                    result += "t";
                    break;

                  default:
                    json || code > 255 ? result += "u" + "0000".slice(hex.length) + hex : "\0" === ch && "0123456789".indexOf(next) < 0 ? result += "0" : result += "\v" === ch ? "v" : "x" + "00".slice(hex.length) + hex;
                }
                return result;
            }
            function escapeDisallowedCharacter(ch) {
                var result = "\\";
                switch (ch) {
                  case "\\":
                    result += "\\";
                    break;

                  case "\n":
                    result += "n";
                    break;

                  case "\r":
                    result += "r";
                    break;

                  case "\u2028":
                    result += "u2028";
                    break;

                  case "\u2029":
                    result += "u2029";
                    break;

                  default:
                    throw new Error("Incorrectly classified character");
                }
                return result;
            }
            function escapeDirective(str) {
                var i, iz, ch, buf, quote;
                for (buf = str, void 0 === buf[0] && (buf = stringToArray(buf)), quote = "double" === quotes ? '"' : "'", 
                i = 0, iz = buf.length; i < iz; i += 1) {
                    if ("'" === (ch = buf[i])) {
                        quote = '"';
                        break;
                    }
                    if ('"' === ch) {
                        quote = "'";
                        break;
                    }
                    "\\" === ch && (i += 1);
                }
                return quote + str + quote;
            }
            function escapeString(str) {
                var i, len, ch, single, result = "", singleQuotes = 0, doubleQuotes = 0;
                for (void 0 === str[0] && (str = stringToArray(str)), i = 0, len = str.length; i < len; i += 1) {
                    if ("'" === (ch = str[i])) singleQuotes += 1; else if ('"' === ch) doubleQuotes += 1; else if ("/" === ch && json) result += "\\"; else {
                        if ("\\\n\r\u2028\u2029".indexOf(ch) >= 0) {
                            result += escapeDisallowedCharacter(ch);
                            continue;
                        }
                        if (json && ch < " " || !(json || escapeless || ch >= " " && ch <= "~")) {
                            result += escapeAllowedCharacter(ch, str[i + 1]);
                            continue;
                        }
                    }
                    result += ch;
                }
                for (single = !("double" === quotes || "auto" === quotes && doubleQuotes < singleQuotes), 
                str = result, result = single ? "'" : '"', void 0 === str[0] && (str = stringToArray(str)), 
                i = 0, len = str.length; i < len; i += 1) ch = str[i], ("'" === ch && single || '"' === ch && !single) && (result += "\\"), 
                result += ch;
                return result + (single ? "'" : '"');
            }
            function isWhiteSpace(ch) {
                return "\t\v\f \xa0".indexOf(ch) >= 0 || ch.charCodeAt(0) >= 5760 && "\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\ufeff".indexOf(ch) >= 0;
            }
            function isLineTerminator(ch) {
                return "\n\r\u2028\u2029".indexOf(ch) >= 0;
            }
            function isIdentifierPart(ch) {
                return "$" === ch || "_" === ch || "\\" === ch || ch >= "a" && ch <= "z" || ch >= "A" && ch <= "Z" || ch >= "0" && ch <= "9" || ch.charCodeAt(0) >= 128 && Regex.NonAsciiIdentifierPart.test(ch);
            }
            function toSourceNode(generated, node) {
                if (null == node) {
                    if (generated instanceof SourceNode) return generated;
                    node = {};
                }
                return null == node.loc ? new SourceNode(null, null, sourceMap, generated) : new SourceNode(node.loc.start.line, node.loc.start.column, !0 === sourceMap ? node.loc.source || null : sourceMap, generated);
            }
            function join(left, right) {
                var leftSource = toSourceNode(left).toString(), rightSource = toSourceNode(right).toString(), leftChar = leftSource.charAt(leftSource.length - 1), rightChar = rightSource.charAt(0);
                return ("+" === leftChar || "-" === leftChar) && leftChar === rightChar || isIdentifierPart(leftChar) && isIdentifierPart(rightChar) ? [ left, " ", right ] : isWhiteSpace(leftChar) || isLineTerminator(leftChar) || isWhiteSpace(rightChar) || isLineTerminator(rightChar) ? [ left, right ] : [ left, space, right ];
            }
            function addIndent(stmt) {
                return [ base, stmt ];
            }
            function withIndent(fn) {
                var previousBase, result;
                return previousBase = base, base += indent, result = fn.call(this, base), base = previousBase, 
                result;
            }
            function calculateSpaces(str) {
                var i;
                for (i = str.length - 1; i >= 0 && !isLineTerminator(str.charAt(i)); i -= 1) ;
                return str.length - 1 - i;
            }
            function adjustMultilineComment(value, specialBase) {
                var array, i, len, line, j, spaces, previousBase;
                for (array = value.split(/\r\n|[\r\n]/), spaces = Number.MAX_VALUE, i = 1, len = array.length; i < len; i += 1) {
                    for (line = array[i], j = 0; j < line.length && isWhiteSpace(line[j]); ) j += 1;
                    spaces > j && (spaces = j);
                }
                for (void 0 !== specialBase ? (previousBase = base, "*" === array[1][spaces] && (specialBase += " "), 
                base = specialBase) : (1 & spaces && (spaces -= 1), previousBase = base), i = 1, 
                len = array.length; i < len; i += 1) array[i] = toSourceNode(addIndent(array[i].slice(spaces))).join("");
                return base = previousBase, array.join("\n");
            }
            function generateComment(comment, specialBase) {
                return "Line" === comment.type ? endsWithLineTerminator(comment.value) ? "//" + comment.value : "//" + comment.value + "\n" : extra.format.indent.adjustMultilineComment && /[\n\r]/.test(comment.value) ? adjustMultilineComment("/*" + comment.value + "*/", specialBase) : "/*" + comment.value + "*/";
            }
            function addCommentsToStatement(stmt, result) {
                var i, len, comment, save, tailingToStatement, specialBase, fragment;
                if (stmt.leadingComments && stmt.leadingComments.length > 0) {
                    for (save = result, comment = stmt.leadingComments[0], result = [], safeConcatenation && stmt.type === Syntax.Program && 0 === stmt.body.length && result.push("\n"), 
                    result.push(generateComment(comment)), endsWithLineTerminator(toSourceNode(result).toString()) || result.push("\n"), 
                    i = 1, len = stmt.leadingComments.length; i < len; i += 1) comment = stmt.leadingComments[i], 
                    fragment = [ generateComment(comment) ], endsWithLineTerminator(toSourceNode(fragment).toString()) || fragment.push("\n"), 
                    result.push(addIndent(fragment));
                    result.push(addIndent(save));
                }
                if (stmt.trailingComments) for (tailingToStatement = !endsWithLineTerminator(toSourceNode(result).toString()), 
                specialBase = stringRepeat(" ", calculateSpaces(toSourceNode([ base, result, indent ]).toString())), 
                i = 0, len = stmt.trailingComments.length; i < len; i += 1) comment = stmt.trailingComments[i], 
                tailingToStatement ? (result = 0 === i ? [ result, indent ] : [ result, specialBase ], 
                result.push(generateComment(comment, specialBase))) : result = [ result, addIndent(generateComment(comment)) ], 
                i === len - 1 || endsWithLineTerminator(toSourceNode(result).toString()) || (result = [ result, "\n" ]);
                return result;
            }
            function parenthesize(text, current, should) {
                return current < should ? [ "(", text, ")" ] : text;
            }
            function maybeBlock(stmt, semicolonOptional, functionBody) {
                var result, noLeadingComment;
                return noLeadingComment = !extra.comment || !stmt.leadingComments, stmt.type === Syntax.BlockStatement && noLeadingComment ? [ space, generateStatement(stmt, {
                    functionBody: functionBody
                }) ] : stmt.type === Syntax.EmptyStatement && noLeadingComment ? ";" : (withIndent(function() {
                    result = [ newline, addIndent(generateStatement(stmt, {
                        semicolonOptional: semicolonOptional,
                        functionBody: functionBody
                    })) ];
                }), result);
            }
            function maybeBlockSuffix(stmt, result) {
                var ends = endsWithLineTerminator(toSourceNode(result).toString());
                return stmt.type !== Syntax.BlockStatement || extra.comment && stmt.leadingComments || ends ? ends ? [ result, base ] : [ result, newline, base ] : [ result, space ];
            }
            function generateVerbatim(expr, option) {
                var i, result;
                for (result = expr[extra.verbatim].split(/\r\n|\n/), i = 1; i < result.length; i++) result[i] = newline + base + result[i];
                return result = parenthesize(result, Precedence.Sequence, option.precedence), toSourceNode(result, expr);
            }
            function generateFunctionBody(node) {
                var result, i, len, expr;
                for (result = [ "(" ], i = 0, len = node.params.length; i < len; i += 1) result.push(node.params[i].name), 
                i + 1 < len && result.push("," + space);
                return result.push(")"), node.expression ? (result.push(space), expr = generateExpression(node.body, {
                    precedence: Precedence.Assignment,
                    allowIn: !0,
                    allowCall: !0
                }), "{" === expr.toString().charAt(0) && (expr = [ "(", expr, ")" ]), result.push(expr)) : result.push(maybeBlock(node.body, !1, !0)), 
                result;
            }
            function generateExpression(expr, option) {
                var result, precedence, type, currentPrecedence, i, len, raw, fragment, multiline, leftChar, leftSource, rightChar, allowIn, allowCall, allowUnparenthesizedNew, property;
                if (precedence = option.precedence, allowIn = option.allowIn, allowCall = option.allowCall, 
                type = expr.type || option.type, extra.verbatim && expr.hasOwnProperty(extra.verbatim)) return generateVerbatim(expr, option);
                switch (type) {
                  case Syntax.SequenceExpression:
                    for (result = [], allowIn |= Precedence.Sequence < precedence, i = 0, len = expr.expressions.length; i < len; i += 1) result.push(generateExpression(expr.expressions[i], {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    })), i + 1 < len && result.push("," + space);
                    result = parenthesize(result, Precedence.Sequence, precedence);
                    break;

                  case Syntax.AssignmentExpression:
                    allowIn |= Precedence.Assignment < precedence, result = parenthesize([ generateExpression(expr.left, {
                        precedence: Precedence.Call,
                        allowIn: allowIn,
                        allowCall: !0
                    }), space + expr.operator + space, generateExpression(expr.right, {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    }) ], Precedence.Assignment, precedence);
                    break;

                  case Syntax.ConditionalExpression:
                    allowIn |= Precedence.Conditional < precedence, result = parenthesize([ generateExpression(expr.test, {
                        precedence: Precedence.LogicalOR,
                        allowIn: allowIn,
                        allowCall: !0
                    }), space + "?" + space, generateExpression(expr.consequent, {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    }), space + ":" + space, generateExpression(expr.alternate, {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    }) ], Precedence.Conditional, precedence);
                    break;

                  case Syntax.LogicalExpression:
                  case Syntax.BinaryExpression:
                    currentPrecedence = BinaryPrecedence[expr.operator], allowIn |= currentPrecedence < precedence, 
                    result = join(generateExpression(expr.left, {
                        precedence: currentPrecedence,
                        allowIn: allowIn,
                        allowCall: !0
                    }), expr.operator), fragment = generateExpression(expr.right, {
                        precedence: currentPrecedence + 1,
                        allowIn: allowIn,
                        allowCall: !0
                    }), "/" === expr.operator && "/" === fragment.toString().charAt(0) ? result.push(" ", fragment) : result = join(result, fragment), 
                    result = "in" !== expr.operator || allowIn ? parenthesize(result, currentPrecedence, precedence) : [ "(", result, ")" ];
                    break;

                  case Syntax.CallExpression:
                    for (result = [ generateExpression(expr.callee, {
                        precedence: Precedence.Call,
                        allowIn: !0,
                        allowCall: !0,
                        allowUnparenthesizedNew: !1
                    }) ], result.push("("), i = 0, len = expr.arguments.length; i < len; i += 1) result.push(generateExpression(expr.arguments[i], {
                        precedence: Precedence.Assignment,
                        allowIn: !0,
                        allowCall: !0
                    })), i + 1 < len && result.push("," + space);
                    result.push(")"), result = allowCall ? parenthesize(result, Precedence.Call, precedence) : [ "(", result, ")" ];
                    break;

                  case Syntax.NewExpression:
                    if (len = expr.arguments.length, allowUnparenthesizedNew = void 0 === option.allowUnparenthesizedNew || option.allowUnparenthesizedNew, 
                    result = join("new", generateExpression(expr.callee, {
                        precedence: Precedence.New,
                        allowIn: !0,
                        allowCall: !1,
                        allowUnparenthesizedNew: allowUnparenthesizedNew && !parentheses && 0 === len
                    })), !allowUnparenthesizedNew || parentheses || len > 0) {
                        for (result.push("("), i = 0; i < len; i += 1) result.push(generateExpression(expr.arguments[i], {
                            precedence: Precedence.Assignment,
                            allowIn: !0,
                            allowCall: !0
                        })), i + 1 < len && result.push("," + space);
                        result.push(")");
                    }
                    result = parenthesize(result, Precedence.New, precedence);
                    break;

                  case Syntax.MemberExpression:
                    result = [ generateExpression(expr.object, {
                        precedence: Precedence.Call,
                        allowIn: !0,
                        allowCall: allowCall,
                        allowUnparenthesizedNew: !1
                    }) ], expr.computed ? result.push("[", generateExpression(expr.property, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: allowCall
                    }), "]") : (expr.object.type === Syntax.Literal && "number" == typeof expr.object.value && result.indexOf(".") < 0 && (/[eExX]/.test(result) || result.length >= 2 && "0" === result[0] || result.push(".")), 
                    result.push("." + expr.property.name)), result = parenthesize(result, Precedence.Member, precedence);
                    break;

                  case Syntax.UnaryExpression:
                    fragment = generateExpression(expr.argument, {
                        precedence: Precedence.Unary,
                        allowIn: !0,
                        allowCall: !0
                    }), "" === space ? result = join(expr.operator, fragment) : (result = [ expr.operator ], 
                    expr.operator.length > 2 ? result = join(result, fragment) : (leftSource = toSourceNode(result).toString(), 
                    leftChar = leftSource.charAt(leftSource.length - 1), rightChar = fragment.toString().charAt(0), 
                    ("+" === leftChar || "-" === leftChar) && leftChar === rightChar || isIdentifierPart(leftChar) && isIdentifierPart(rightChar) ? result.push(" ", fragment) : result.push(fragment))), 
                    result = parenthesize(result, Precedence.Unary, precedence);
                    break;

                  case Syntax.YieldExpression:
                    result = expr.delegate ? "yield*" : "yield", expr.argument && (result = join(result, generateExpression(expr.argument, {
                        precedence: Precedence.Assignment,
                        allowIn: !0,
                        allowCall: !0
                    })));
                    break;

                  case Syntax.UpdateExpression:
                    result = expr.prefix ? parenthesize([ expr.operator, generateExpression(expr.argument, {
                        precedence: Precedence.Unary,
                        allowIn: !0,
                        allowCall: !0
                    }) ], Precedence.Unary, precedence) : parenthesize([ generateExpression(expr.argument, {
                        precedence: Precedence.Postfix,
                        allowIn: !0,
                        allowCall: !0
                    }), expr.operator ], Precedence.Postfix, precedence);
                    break;

                  case Syntax.FunctionExpression:
                    result = "function", expr.id ? result += " " + expr.id.name : result += space, result = [ result, generateFunctionBody(expr) ];
                    break;

                  case Syntax.ArrayPattern:
                  case Syntax.ArrayExpression:
                    if (void 0 === expr.elements || !expr.elements.length) {
                        result = "[]";
                        break;
                    }
                    multiline = expr.elements.length > 1, result = [ "[", multiline ? newline : "" ], 
                    withIndent(function(indent) {
                        for (i = 0, len = expr.elements.length; i < len; i += 1) expr.elements[i] ? result.push(multiline ? indent : "", generateExpression(expr.elements[i], {
                            precedence: Precedence.Assignment,
                            allowIn: !0,
                            allowCall: !0
                        })) : (multiline && result.push(indent), i + 1 === len && result.push(",")), i + 1 < len && result.push("," + (multiline ? newline : space));
                    }), multiline && !endsWithLineTerminator(toSourceNode(result).toString()) && result.push(newline), 
                    result.push(multiline ? base : "", "]");
                    break;

                  case Syntax.Property:
                    "get" === expr.kind || "set" === expr.kind ? result = [ expr.kind + " ", generateExpression(expr.key, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), generateFunctionBody(expr.value) ] : expr.shorthand ? result = generateExpression(expr.key, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }) : expr.method ? (result = [], expr.value.generator && result.push("*"), result.push(generateExpression(expr.key, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), generateFunctionBody(expr.value))) : result = [ generateExpression(expr.key, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), ":" + space, generateExpression(expr.value, {
                        precedence: Precedence.Assignment,
                        allowIn: !0,
                        allowCall: !0
                    }) ];
                    break;

                  case Syntax.ObjectExpression:
                    if (null != expr.properties && void 0 !== expr.properties || console.debug(expr), 
                    !expr.properties.length) {
                        result = "{}";
                        break;
                    }
                    if (multiline = expr.properties.length > 1, withIndent(function(indent) {
                        fragment = generateExpression(expr.properties[0], {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0,
                            type: Syntax.Property
                        });
                    }), !multiline && !hasLineTerminator(toSourceNode(fragment).toString())) {
                        result = [ "{", space, fragment, space, "}" ];
                        break;
                    }
                    withIndent(function(indent) {
                        if (result = [ "{", newline, indent, fragment ], multiline) for (result.push("," + newline), 
                        i = 1, len = expr.properties.length; i < len; i += 1) result.push(indent, generateExpression(expr.properties[i], {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0,
                            type: Syntax.Property
                        })), i + 1 < len && result.push("," + newline);
                    }), endsWithLineTerminator(toSourceNode(result).toString()) || result.push(newline), 
                    result.push(base, "}");
                    break;

                  case Syntax.ObjectPattern:
                    if (!expr.properties.length) {
                        result = "{}";
                        break;
                    }
                    if (multiline = !1, 1 === expr.properties.length) property = expr.properties[0], 
                    property.value.type !== Syntax.Identifier && (multiline = !0); else for (i = 0, 
                    len = expr.properties.length; i < len; i += 1) if (property = expr.properties[i], 
                    !property.shorthand) {
                        multiline = !0;
                        break;
                    }
                    result = [ "{", multiline ? newline : "" ], withIndent(function(indent) {
                        for (i = 0, len = expr.properties.length; i < len; i += 1) result.push(multiline ? indent : "", generateExpression(expr.properties[i], {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        })), i + 1 < len && result.push("," + (multiline ? newline : space));
                    }), multiline && !endsWithLineTerminator(toSourceNode(result).toString()) && result.push(newline), 
                    result.push(multiline ? base : "", "}");
                    break;

                  case Syntax.ThisExpression:
                    result = "this";
                    break;

                  case Syntax.Identifier:
                    result = expr.name;
                    break;

                  case Syntax.Literal:
                    if (expr.hasOwnProperty("raw") && parse) try {
                        if (raw = parse(expr.raw).body[0].expression, raw.type === Syntax.Literal && raw.value === expr.value) {
                            result = expr.raw;
                            break;
                        }
                    } catch (e) {}
                    if (null === expr.value) {
                        result = "null";
                        break;
                    }
                    if ("string" == typeof expr.value) {
                        result = escapeString(expr.value);
                        break;
                    }
                    if ("number" == typeof expr.value) {
                        result = generateNumber(expr.value);
                        break;
                    }
                    result = expr.value.toString();
                    break;

                  case Syntax.LiteralSeq:
                    result = escapeString(expr.value);
                    break;

                  case Syntax.ComprehensionExpression:
                    if (result = [ "[", generateExpression(expr.body, {
                        precedence: Precedence.Assignment,
                        allowIn: !0,
                        allowCall: !0
                    }) ], expr.blocks) for (i = 0, len = expr.blocks.length; i < len; i += 1) fragment = generateExpression(expr.blocks[i], {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), result = join(result, fragment);
                    expr.filter && (result = join(result, "if" + space), fragment = generateExpression(expr.filter, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), result = extra.moz.parenthesizedComprehensionBlock ? join(result, [ "(", fragment, ")" ]) : join(result, fragment)), 
                    result.push("]");
                    break;

                  case Syntax.ComprehensionBlock:
                    fragment = expr.left.type === Syntax.VariableDeclaration ? [ expr.left.kind + " ", generateStatement(expr.left.declarations[0], {
                        allowIn: !1
                    }) ] : generateExpression(expr.left, {
                        precedence: Precedence.Call,
                        allowIn: !0,
                        allowCall: !0
                    }), fragment = join(fragment, expr.of ? "of" : "in"), fragment = join(fragment, generateExpression(expr.right, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    })), result = extra.moz.parenthesizedComprehensionBlock ? [ "for" + space + "(", fragment, ")" ] : join("for" + space, fragment);
                    break;

                  default:
                    throw console.log("error processing expr", expr), new Error("Unknown expression type: " + expr.type);
                }
                return toSourceNode(result, expr);
            }
            function generateStatement(stmt, option) {
                var i, len, result, node, allowIn, functionBody, directiveContext, fragment, semicolon;
                switch (allowIn = !0, semicolon = ";", functionBody = !1, directiveContext = !1, 
                option && (allowIn = void 0 === option.allowIn || option.allowIn, semicolons || !0 !== option.semicolonOptional || (semicolon = ""), 
                functionBody = option.functionBody, directiveContext = option.directiveContext), 
                stmt.type) {
                  case Syntax.BlockStatement:
                    result = [ "{", newline ], withIndent(function() {
                        for (i = 0, len = stmt.body.length; i < len; i += 1) fragment = addIndent(generateStatement(stmt.body[i], {
                            semicolonOptional: i === len - 1,
                            directiveContext: functionBody
                        })), result.push(fragment), endsWithLineTerminator(toSourceNode(fragment).toString()) || result.push(newline);
                    }), result.push(addIndent("}"));
                    break;

                  case Syntax.BreakStatement:
                    result = stmt.label ? "break " + stmt.label.name + semicolon : "break" + semicolon;
                    break;

                  case Syntax.ContinueStatement:
                    result = stmt.label ? "continue " + stmt.label.name + semicolon : "continue" + semicolon;
                    break;

                  case Syntax.DirectiveStatement:
                    result = stmt.raw ? stmt.raw + semicolon : escapeDirective(stmt.directive) + semicolon;
                    break;

                  case Syntax.DoWhileStatement:
                    result = join("do", maybeBlock(stmt.body)), result = maybeBlockSuffix(stmt.body, result), 
                    result = join(result, [ "while" + space + "(", generateExpression(stmt.test, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }), ")" + semicolon ]);
                    break;

                  case Syntax.CatchClause:
                    withIndent(function() {
                        result = [ "catch" + space + "(", generateExpression(stmt.param, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")" ];
                    }), result.push(maybeBlock(stmt.body));
                    break;

                  case Syntax.DebuggerStatement:
                    result = "debugger" + semicolon;
                    break;

                  case Syntax.EmptyStatement:
                    result = ";";
                    break;

                  case Syntax.ExpressionStatement:
                    result = [ generateExpression(stmt.expression, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    }) ], "{" === result.toString().charAt(0) || "function" === result.toString().slice(0, 8) && " (".indexOf(result.toString().charAt(8)) >= 0 || directive && directiveContext && stmt.expression.type === Syntax.Literal && "string" == typeof stmt.expression.value ? result = [ "(", result, ")" + semicolon ] : result.push(semicolon);
                    break;

                  case Syntax.VariableDeclarator:
                    result = stmt.init ? [ generateExpression(stmt.id, {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    }) + space + "=" + space, generateExpression(stmt.init, {
                        precedence: Precedence.Assignment,
                        allowIn: allowIn,
                        allowCall: !0
                    }) ] : stmt.id.name;
                    break;

                  case Syntax.VariableDeclaration:
                    result = [ stmt.kind ], 1 === stmt.declarations.length && stmt.declarations[0].init && stmt.declarations[0].init.type === Syntax.FunctionExpression ? result.push(" ", generateStatement(stmt.declarations[0], {
                        allowIn: allowIn
                    })) : withIndent(function() {
                        for (node = stmt.declarations[0], extra.comment && node.leadingComments ? result.push("\n", addIndent(generateStatement(node, {
                            allowIn: allowIn
                        }))) : result.push(" ", generateStatement(node, {
                            allowIn: allowIn
                        })), i = 1, len = stmt.declarations.length; i < len; i += 1) node = stmt.declarations[i], 
                        extra.comment && node.leadingComments ? result.push("," + newline, addIndent(generateStatement(node, {
                            allowIn: allowIn
                        }))) : result.push("," + space, generateStatement(node, {
                            allowIn: allowIn
                        }));
                    }), result.push(semicolon);
                    break;

                  case Syntax.ThrowStatement:
                    result = [ join("throw", generateExpression(stmt.argument, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    })), semicolon ];
                    break;

                  case Syntax.TryStatement:
                    for (result = [ "try", maybeBlock(stmt.block) ], result = maybeBlockSuffix(stmt.block, result), 
                    i = 0, len = stmt.handlers.length; i < len; i += 1) result = join(result, generateStatement(stmt.handlers[i])), 
                    (stmt.finalizer || i + 1 !== len) && (result = maybeBlockSuffix(stmt.handlers[i].body, result));
                    stmt.finalizer && (result = join(result, [ "finally", maybeBlock(stmt.finalizer) ]));
                    break;

                  case Syntax.SwitchStatement:
                    if (withIndent(function() {
                        result = [ "switch" + space + "(", generateExpression(stmt.discriminant, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")" + space + "{" + newline ];
                    }), stmt.cases) for (i = 0, len = stmt.cases.length; i < len; i += 1) fragment = addIndent(generateStatement(stmt.cases[i], {
                        semicolonOptional: i === len - 1
                    })), result.push(fragment), endsWithLineTerminator(toSourceNode(fragment).toString()) || result.push(newline);
                    result.push(addIndent("}"));
                    break;

                  case Syntax.SwitchCase:
                    withIndent(function() {
                        for (result = stmt.test ? [ join("case", generateExpression(stmt.test, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        })), ":" ] : [ "default:" ], i = 0, len = stmt.consequent.length, len && stmt.consequent[0].type === Syntax.BlockStatement && (fragment = maybeBlock(stmt.consequent[0]), 
                        result.push(fragment), i = 1), i === len || endsWithLineTerminator(toSourceNode(result).toString()) || result.push(newline); i < len; i += 1) fragment = addIndent(generateStatement(stmt.consequent[i], {
                            semicolonOptional: i === len - 1 && "" === semicolon
                        })), result.push(fragment), i + 1 === len || endsWithLineTerminator(toSourceNode(fragment).toString()) || result.push(newline);
                    });
                    break;

                  case Syntax.IfStatement:
                    withIndent(function() {
                        result = [ "if" + space + "(", generateExpression(stmt.test, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")" ];
                    }), stmt.alternate ? (result.push(maybeBlock(stmt.consequent)), result = maybeBlockSuffix(stmt.consequent, result), 
                    result = stmt.alternate.type === Syntax.IfStatement ? join(result, [ "else ", generateStatement(stmt.alternate, {
                        semicolonOptional: "" === semicolon
                    }) ]) : join(result, join("else", maybeBlock(stmt.alternate, "" === semicolon)))) : result.push(maybeBlock(stmt.consequent, "" === semicolon));
                    break;

                  case Syntax.ForStatement:
                    withIndent(function() {
                        result = [ "for" + space + "(" ], stmt.init ? stmt.init.type === Syntax.VariableDeclaration ? result.push(generateStatement(stmt.init, {
                            allowIn: !1
                        })) : result.push(generateExpression(stmt.init, {
                            precedence: Precedence.Sequence,
                            allowIn: !1,
                            allowCall: !0
                        }), ";") : result.push(";"), stmt.test ? result.push(space, generateExpression(stmt.test, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ";") : result.push(";"), stmt.update ? result.push(space, generateExpression(stmt.update, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")") : result.push(")");
                    }), result.push(maybeBlock(stmt.body, "" === semicolon));
                    break;

                  case Syntax.ForInStatement:
                    result = [ "for" + space + "(" ], withIndent(function() {
                        stmt.left.type === Syntax.VariableDeclaration ? withIndent(function() {
                            result.push(stmt.left.kind + " ", generateStatement(stmt.left.declarations[0], {
                                allowIn: !1
                            }));
                        }) : result.push(generateExpression(stmt.left, {
                            precedence: Precedence.Call,
                            allowIn: !0,
                            allowCall: !0
                        })), result = join(result, "in"), result = [ join(result, generateExpression(stmt.right, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        })), ")" ];
                    }), result.push(maybeBlock(stmt.body, "" === semicolon));
                    break;

                  case Syntax.LabeledStatement:
                    result = [ stmt.label.name + ":", maybeBlock(stmt.body, "" === semicolon) ];
                    break;

                  case Syntax.Program:
                    for (len = stmt.body.length, result = [ safeConcatenation && len > 0 ? "\n" : "" ], 
                    i = 0; i < len; i += 1) fragment = addIndent(generateStatement(stmt.body[i], {
                        semicolonOptional: !safeConcatenation && i === len - 1,
                        directiveContext: !0
                    })), result.push(fragment), i + 1 < len && !endsWithLineTerminator(toSourceNode(fragment).toString()) && result.push(newline);
                    break;

                  case Syntax.FunctionDeclaration:
                    result = [ (stmt.generator && !extra.moz.starlessGenerator ? "function* " : "function ") + stmt.id.name, generateFunctionBody(stmt) ];
                    break;

                  case Syntax.ReturnStatement:
                    result = stmt.argument ? [ join("return", generateExpression(stmt.argument, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    })), semicolon ] : [ "return" + semicolon ];
                    break;

                  case Syntax.WhileStatement:
                    withIndent(function() {
                        result = [ "while" + space + "(", generateExpression(stmt.test, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")" ];
                    }), result.push(maybeBlock(stmt.body, "" === semicolon));
                    break;

                  case Syntax.WithStatement:
                    withIndent(function() {
                        result = [ "with" + space + "(", generateExpression(stmt.object, {
                            precedence: Precedence.Sequence,
                            allowIn: !0,
                            allowCall: !0
                        }), ")" ];
                    }), result.push(maybeBlock(stmt.body, "" === semicolon));
                    break;

                  default:
                    throw new Error("Unknown statement type: " + stmt.type);
                }
                return extra.comment && (result = addCommentsToStatement(stmt, result)), fragment = toSourceNode(result).toString(), 
                stmt.type !== Syntax.Program || safeConcatenation || "" !== newline || "\n" !== fragment.charAt(fragment.length - 1) || (result = toSourceNode(result).replaceRight(/\s+$/, "")), 
                toSourceNode(result, stmt);
            }
            function generate(node, options) {
                var result, pair, defaultOptions = getDefaultOptions();
                switch (null != options ? ("string" == typeof options.indent && (defaultOptions.format.indent.style = options.indent), 
                "number" == typeof options.base && (defaultOptions.format.indent.base = options.base), 
                options = updateDeeply(defaultOptions, options), indent = options.format.indent.style, 
                base = "string" == typeof options.base ? options.base : stringRepeat(indent, options.format.indent.base)) : (options = defaultOptions, 
                indent = options.format.indent.style, base = stringRepeat(indent, options.format.indent.base)), 
                json = options.format.json, renumber = options.format.renumber, hexadecimal = !json && options.format.hexadecimal, 
                quotes = json ? "double" : options.format.quotes, escapeless = options.format.escapeless, 
                options.format.compact ? newline = space = indent = base = "" : (newline = "\n", 
                space = " "), parentheses = options.format.parentheses, semicolons = options.format.semicolons, 
                safeConcatenation = options.format.safeConcatenation, directive = options.directive, 
                parse = json ? null : options.parse, sourceMap = options.sourceMap, extra = options, 
                SourceNode = sourceMap ? exports.browser ? global.sourceMap.SourceNode : require("source-map").SourceNode : SourceNodeMock, 
                node.type) {
                  case Syntax.BlockStatement:
                  case Syntax.BreakStatement:
                  case Syntax.CatchClause:
                  case Syntax.ContinueStatement:
                  case Syntax.DirectiveStatement:
                  case Syntax.DoWhileStatement:
                  case Syntax.DebuggerStatement:
                  case Syntax.EmptyStatement:
                  case Syntax.ExpressionStatement:
                  case Syntax.ForStatement:
                  case Syntax.ForInStatement:
                  case Syntax.FunctionDeclaration:
                  case Syntax.IfStatement:
                  case Syntax.LabeledStatement:
                  case Syntax.Program:
                  case Syntax.ReturnStatement:
                  case Syntax.SwitchStatement:
                  case Syntax.SwitchCase:
                  case Syntax.ThrowStatement:
                  case Syntax.TryStatement:
                  case Syntax.VariableDeclaration:
                  case Syntax.VariableDeclarator:
                  case Syntax.WhileStatement:
                  case Syntax.WithStatement:
                    result = generateStatement(node);
                    break;

                  case Syntax.AssignmentExpression:
                  case Syntax.ArrayExpression:
                  case Syntax.ArrayPattern:
                  case Syntax.BinaryExpression:
                  case Syntax.CallExpression:
                  case Syntax.ConditionalExpression:
                  case Syntax.FunctionExpression:
                  case Syntax.Identifier:
                  case Syntax.Literal:
                  case Syntax.LogicalExpression:
                  case Syntax.MemberExpression:
                  case Syntax.NewExpression:
                  case Syntax.ObjectExpression:
                  case Syntax.ObjectPattern:
                  case Syntax.Property:
                  case Syntax.SequenceExpression:
                  case Syntax.ThisExpression:
                  case Syntax.UnaryExpression:
                  case Syntax.UpdateExpression:
                  case Syntax.YieldExpression:
                  case Syntax.LiteralSeq:
                    result = generateExpression(node, {
                        precedence: Precedence.Sequence,
                        allowIn: !0,
                        allowCall: !0
                    });
                    break;

                  default:
                    throw new Error("Unknown node type: " + node.type);
                }
                return sourceMap ? (pair = result.toStringWithSourceMap({
                    file: options.sourceMap,
                    sourceRoot: options.sourceMapRoot
                }), options.sourceMapWithCode ? pair : pair.map.toString()) : result.toString();
            }
            function upperBound(array, func) {
                var diff, len, i, current;
                for (len = array.length, i = 0; len; ) diff = len >>> 1, current = i + diff, func(array[current]) ? len = diff : (i = current + 1, 
                len -= diff + 1);
                return i;
            }
            function extendCommentRange(comment, tokens) {
                var target, token;
                return target = upperBound(tokens, function(token) {
                    return token.range[0] > comment.range[0];
                }), comment.extendedRange = [ comment.range[0], comment.range[1] ], target !== tokens.length && (comment.extendedRange[1] = tokens[target].range[0]), 
                target -= 1, target >= 0 && (target < tokens.length ? comment.extendedRange[0] = tokens[target].range[1] : token.length && (comment.extendedRange[1] = tokens[tokens.length - 1].range[0])), 
                comment;
            }
            function attachComments(tree, providedComments, tokens) {
                var comment, len, i, comments = [];
                if (!tree.range) throw new Error("attachComments needs range information");
                if (!tokens.length) {
                    if (providedComments.length) {
                        for (i = 0, len = providedComments.length; i < len; i += 1) comment = deepCopy(providedComments[i]), 
                        comment.extendedRange = [ 0, tree.range[0] ], comments.push(comment);
                        tree.leadingComments = comments;
                    }
                    return tree;
                }
                for (i = 0, len = providedComments.length; i < len; i += 1) comments.push(extendCommentRange(deepCopy(providedComments[i]), tokens));
                return traverse(tree, {
                    cursor: 0,
                    enter: function(node) {
                        for (var comment; this.cursor < comments.length && (comment = comments[this.cursor], 
                        !(comment.extendedRange[1] > node.range[0])); ) comment.extendedRange[1] === node.range[0] ? (node.leadingComments || (node.leadingComments = []), 
                        node.leadingComments.push(comment), comments.splice(this.cursor, 1)) : this.cursor += 1;
                        return this.cursor === comments.length ? VisitorOption.Break : comments[this.cursor].extendedRange[0] > node.range[1] ? VisitorOption.Skip : void 0;
                    }
                }), traverse(tree, {
                    cursor: 0,
                    leave: function(node) {
                        for (var comment; this.cursor < comments.length && (comment = comments[this.cursor], 
                        !(node.range[1] < comment.extendedRange[0])); ) node.range[1] === comment.extendedRange[0] ? (node.trailingComments || (node.trailingComments = []), 
                        node.trailingComments.push(comment), comments.splice(this.cursor, 1)) : this.cursor += 1;
                        return this.cursor === comments.length ? VisitorOption.Break : comments[this.cursor].extendedRange[0] > node.range[1] ? VisitorOption.Skip : void 0;
                    }
                }), tree;
            }
            var Syntax, Precedence, BinaryPrecedence, Regex, VisitorOption, SourceNode, isArray, base, indent, json, renumber, hexadecimal, quotes, escapeless, newline, space, parentheses, semicolons, safeConcatenation, directive, extra, parse, sourceMap, traverse;
            traverse = require("estraverse").traverse, Syntax = {
                AssignmentExpression: "AssignmentExpression",
                ArrayExpression: "ArrayExpression",
                ArrayPattern: "ArrayPattern",
                BlockStatement: "BlockStatement",
                BinaryExpression: "BinaryExpression",
                BreakStatement: "BreakStatement",
                CallExpression: "CallExpression",
                CatchClause: "CatchClause",
                ComprehensionBlock: "ComprehensionBlock",
                ComprehensionExpression: "ComprehensionExpression",
                ConditionalExpression: "ConditionalExpression",
                ContinueStatement: "ContinueStatement",
                DirectiveStatement: "DirectiveStatement",
                DoWhileStatement: "DoWhileStatement",
                DebuggerStatement: "DebuggerStatement",
                EmptyStatement: "EmptyStatement",
                ExpressionStatement: "ExpressionStatement",
                ForStatement: "ForStatement",
                ForInStatement: "ForInStatement",
                FunctionDeclaration: "FunctionDeclaration",
                FunctionExpression: "FunctionExpression",
                Identifier: "Identifier",
                IfStatement: "IfStatement",
                Literal: "Literal",
                LabeledStatement: "LabeledStatement",
                LogicalExpression: "LogicalExpression",
                MemberExpression: "MemberExpression",
                NewExpression: "NewExpression",
                ObjectExpression: "ObjectExpression",
                ObjectPattern: "ObjectPattern",
                Program: "Program",
                Property: "Property",
                ReturnStatement: "ReturnStatement",
                SequenceExpression: "SequenceExpression",
                SwitchStatement: "SwitchStatement",
                SwitchCase: "SwitchCase",
                ThisExpression: "ThisExpression",
                ThrowStatement: "ThrowStatement",
                TryStatement: "TryStatement",
                UnaryExpression: "UnaryExpression",
                UpdateExpression: "UpdateExpression",
                VariableDeclaration: "VariableDeclaration",
                VariableDeclarator: "VariableDeclarator",
                WhileStatement: "WhileStatement",
                WithStatement: "WithStatement",
                YieldExpression: "YieldExpression",
                LiteralSeq: "LiteralSeq"
            }, Precedence = {
                Sequence: 0,
                Assignment: 1,
                Conditional: 2,
                LogicalOR: 3,
                LogicalAND: 4,
                BitwiseOR: 5,
                BitwiseXOR: 6,
                BitwiseAND: 7,
                Equality: 8,
                Relational: 9,
                BitwiseSHIFT: 10,
                Additive: 11,
                Multiplicative: 12,
                Unary: 13,
                Postfix: 14,
                Call: 15,
                New: 16,
                Member: 17,
                Primary: 18
            }, BinaryPrecedence = {
                "||": Precedence.LogicalOR,
                "&&": Precedence.LogicalAND,
                "|": Precedence.BitwiseOR,
                "^": Precedence.BitwiseXOR,
                "&": Precedence.BitwiseAND,
                "==": Precedence.Equality,
                "!=": Precedence.Equality,
                "===": Precedence.Equality,
                "!==": Precedence.Equality,
                is: Precedence.Equality,
                isnt: Precedence.Equality,
                "<": Precedence.Relational,
                ">": Precedence.Relational,
                "<=": Precedence.Relational,
                ">=": Precedence.Relational,
                in: Precedence.Relational,
                instanceof: Precedence.Relational,
                "<<": Precedence.BitwiseSHIFT,
                ">>": Precedence.BitwiseSHIFT,
                ">>>": Precedence.BitwiseSHIFT,
                "+": Precedence.Additive,
                "-": Precedence.Additive,
                "*": Precedence.Multiplicative,
                "%": Precedence.Multiplicative,
                "/": Precedence.Multiplicative
            }, Regex = {
                NonAsciiIdentifierPart: new RegExp("[\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0300-\u0374\u0376\u0377\u037a-\u037d\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u0483-\u0487\u048a-\u0527\u0531-\u0556\u0559\u0561-\u0587\u0591-\u05bd\u05bf\u05c1\u05c2\u05c4\u05c5\u05c7\u05d0-\u05ea\u05f0-\u05f2\u0610-\u061a\u0620-\u0669\u066e-\u06d3\u06d5-\u06dc\u06df-\u06e8\u06ea-\u06fc\u06ff\u0710-\u074a\u074d-\u07b1\u07c0-\u07f5\u07fa\u0800-\u082d\u0840-\u085b\u08a0\u08a2-\u08ac\u08e4-\u08fe\u0900-\u0963\u0966-\u096f\u0971-\u0977\u0979-\u097f\u0981-\u0983\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bc-\u09c4\u09c7\u09c8\u09cb-\u09ce\u09d7\u09dc\u09dd\u09df-\u09e3\u09e6-\u09f1\u0a01-\u0a03\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a3c\u0a3e-\u0a42\u0a47\u0a48\u0a4b-\u0a4d\u0a51\u0a59-\u0a5c\u0a5e\u0a66-\u0a75\u0a81-\u0a83\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abc-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ad0\u0ae0-\u0ae3\u0ae6-\u0aef\u0b01-\u0b03\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3c-\u0b44\u0b47\u0b48\u0b4b-\u0b4d\u0b56\u0b57\u0b5c\u0b5d\u0b5f-\u0b63\u0b66-\u0b6f\u0b71\u0b82\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd0\u0bd7\u0be6-\u0bef\u0c01-\u0c03\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c33\u0c35-\u0c39\u0c3d-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55\u0c56\u0c58\u0c59\u0c60-\u0c63\u0c66-\u0c6f\u0c82\u0c83\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbc-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5\u0cd6\u0cde\u0ce0-\u0ce3\u0ce6-\u0cef\u0cf1\u0cf2\u0d02\u0d03\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d-\u0d44\u0d46-\u0d48\u0d4a-\u0d4e\u0d57\u0d60-\u0d63\u0d66-\u0d6f\u0d7a-\u0d7f\u0d82\u0d83\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0df2\u0df3\u0e01-\u0e3a\u0e40-\u0e4e\u0e50-\u0e59\u0e81\u0e82\u0e84\u0e87\u0e88\u0e8a\u0e8d\u0e94-\u0e97\u0e99-\u0e9f\u0ea1-\u0ea3\u0ea5\u0ea7\u0eaa\u0eab\u0ead-\u0eb9\u0ebb-\u0ebd\u0ec0-\u0ec4\u0ec6\u0ec8-\u0ecd\u0ed0-\u0ed9\u0edc-\u0edf\u0f00\u0f18\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e-\u0f47\u0f49-\u0f6c\u0f71-\u0f84\u0f86-\u0f97\u0f99-\u0fbc\u0fc6\u1000-\u1049\u1050-\u109d\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u135d-\u135f\u1380-\u138f\u13a0-\u13f4\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f0\u1700-\u170c\u170e-\u1714\u1720-\u1734\u1740-\u1753\u1760-\u176c\u176e-\u1770\u1772\u1773\u1780-\u17d3\u17d7\u17dc\u17dd\u17e0-\u17e9\u180b-\u180d\u1810-\u1819\u1820-\u1877\u1880-\u18aa\u18b0-\u18f5\u1900-\u191c\u1920-\u192b\u1930-\u193b\u1946-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u19d0-\u19d9\u1a00-\u1a1b\u1a20-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1aa7\u1b00-\u1b4b\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1bf3\u1c00-\u1c37\u1c40-\u1c49\u1c4d-\u1c7d\u1cd0-\u1cd2\u1cd4-\u1cf6\u1d00-\u1de6\u1dfc-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u200c\u200d\u203f\u2040\u2054\u2071\u207f\u2090-\u209c\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d7f-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2de0-\u2dff\u2e2f\u3005-\u3007\u3021-\u302f\u3031-\u3035\u3038-\u303c\u3041-\u3096\u3099\u309a\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312d\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fcc\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua62b\ua640-\ua66f\ua674-\ua67d\ua67f-\ua697\ua69f-\ua6f1\ua717-\ua71f\ua722-\ua788\ua78b-\ua78e\ua790-\ua793\ua7a0-\ua7aa\ua7f8-\ua827\ua840-\ua873\ua880-\ua8c4\ua8d0-\ua8d9\ua8e0-\ua8f7\ua8fb\ua900-\ua92d\ua930-\ua953\ua960-\ua97c\ua980-\ua9c0\ua9cf-\ua9d9\uaa00-\uaa36\uaa40-\uaa4d\uaa50-\uaa59\uaa60-\uaa76\uaa7a\uaa7b\uaa80-\uaac2\uaadb-\uaadd\uaae0-\uaaef\uaaf2-\uaaf6\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uabc0-\uabea\uabec\uabed\uabf0-\uabf9\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe00-\ufe0f\ufe20-\ufe26\ufe33\ufe34\ufe4d-\ufe4f\ufe70-\ufe74\ufe76-\ufefc\uff10-\uff19\uff21-\uff3a\uff3f\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]")
            }, isArray = Array.isArray, isArray || (isArray = function(array) {
                return "[object Array]" === Object.prototype.toString.call(array);
            }), SourceNodeMock.prototype.toString = function() {
                var i, iz, node, res = "";
                for (i = 0, iz = this.children.length; i < iz; ++i) node = this.children[i], res += node instanceof SourceNodeMock ? node.toString() : node;
                return res;
            }, SourceNodeMock.prototype.replaceRight = function(pattern, replacement) {
                var last = this.children[this.children.length - 1];
                return last instanceof SourceNodeMock ? last.replaceRight(pattern, replacement) : "string" == typeof last ? this.children[this.children.length - 1] = last.replace(pattern, replacement) : this.children.push("".replace(pattern, replacement)), 
                this;
            }, SourceNodeMock.prototype.join = function(sep) {
                var i, iz, result;
                if (result = [], (iz = this.children.length) > 0) {
                    for (i = 0, iz -= 1; i < iz; ++i) result.push(this.children[i], sep);
                    result.push(this.children[iz]), this.children = result;
                }
                return this;
            }, VisitorOption = {
                Break: 1,
                Skip: 2
            }, exports.version = "0.0.16-dev", exports.generate = generate, exports.attachComments = attachComments, 
            exports.browser = !1;
        }();
    }), require.define("/node_modules/estraverse/package.json", function(require, module, exports, __dirname, __filename, process, global) {
        module.exports = {
            main: "estraverse.js"
        };
    }), require.define("/node_modules/estraverse/estraverse.js", function(require, module, exports, __dirname, __filename, process, global) {
        !function(factory) {
            "use strict";
            "function" == typeof define && define.amd ? define([ "exports" ], factory) : factory(void 0 !== exports ? exports : window.estraverse = {});
        }(function(exports) {
            "use strict";
            function traverse(top, visitor) {
                var worklist, leavelist, node, nodeType, ret, current, current2, candidates, candidate, marker = {};
                for (worklist = [ top ], leavelist = [ null ]; worklist.length; ) if (node = worklist.pop(), 
                nodeType = node.type, node === marker) {
                    if (node = leavelist.pop(), (ret = visitor.leave ? visitor.leave(node, leavelist[leavelist.length - 1]) : void 0) === VisitorOption.Break) return;
                } else if (node) {
                    if (wrappers.hasOwnProperty(nodeType) && (node = node.node, nodeType = wrappers[nodeType]), 
                    (ret = visitor.enter ? visitor.enter(node, leavelist[leavelist.length - 1]) : void 0) === VisitorOption.Break) return;
                    if (worklist.push(marker), leavelist.push(node), ret !== VisitorOption.Skip) for (candidates = VisitorKeys[nodeType], 
                    current = candidates.length; (current -= 1) >= 0; ) if (candidate = node[candidates[current]]) if (isArray(candidate)) for (current2 = candidate.length; (current2 -= 1) >= 0; ) candidate[current2] && (nodeType === Syntax.ObjectExpression && "properties" === candidates[current] && null == candidates[current].type ? worklist.push({
                        type: "PropertyWrapper",
                        node: candidate[current2]
                    }) : worklist.push(candidate[current2])); else worklist.push(candidate);
                }
            }
            function replace(top, visitor) {
                function notify(v) {
                    ret = v;
                }
                var worklist, leavelist, node, nodeType, target, tuple, ret, current, current2, candidates, candidate, result, marker = {};
                for (result = {
                    top: top
                }, tuple = [ top, result, "top" ], worklist = [ tuple ], leavelist = [ tuple ]; worklist.length; ) if ((tuple = worklist.pop()) === marker) {
                    if (tuple = leavelist.pop(), ret = void 0, visitor.leave && (node = tuple[0], target = visitor.leave(tuple[0], leavelist[leavelist.length - 1][0], notify), 
                    void 0 !== target && (node = target), tuple[1][tuple[2]] = node), ret === VisitorOption.Break) return result.top;
                } else if (tuple[0]) {
                    if (ret = void 0, node = tuple[0], nodeType = node.type, wrappers.hasOwnProperty(nodeType) && (tuple[0] = node = node.node, 
                    nodeType = wrappers[nodeType]), visitor.enter && (target = visitor.enter(tuple[0], leavelist[leavelist.length - 1][0], notify), 
                    void 0 !== target && (node = target), tuple[1][tuple[2]] = node, tuple[0] = node), 
                    ret === VisitorOption.Break) return result.top;
                    if (tuple[0] && (worklist.push(marker), leavelist.push(tuple), ret !== VisitorOption.Skip)) for (candidates = VisitorKeys[nodeType], 
                    current = candidates.length; (current -= 1) >= 0; ) if (candidate = node[candidates[current]]) if (isArray(candidate)) for (current2 = candidate.length; (current2 -= 1) >= 0; ) candidate[current2] && (nodeType === Syntax.ObjectExpression && "properties" === candidates[current] && null == candidates[current].type ? worklist.push([ {
                        type: "PropertyWrapper",
                        node: candidate[current2]
                    }, candidate, current2 ]) : worklist.push([ candidate[current2], candidate, current2 ])); else worklist.push([ candidate, node, candidates[current] ]);
                }
                return result.top;
            }
            var Syntax, isArray, VisitorOption, VisitorKeys, wrappers;
            Syntax = {
                AssignmentExpression: "AssignmentExpression",
                ArrayExpression: "ArrayExpression",
                BlockStatement: "BlockStatement",
                BinaryExpression: "BinaryExpression",
                BreakStatement: "BreakStatement",
                CallExpression: "CallExpression",
                CatchClause: "CatchClause",
                ConditionalExpression: "ConditionalExpression",
                ContinueStatement: "ContinueStatement",
                DebuggerStatement: "DebuggerStatement",
                DirectiveStatement: "DirectiveStatement",
                DoWhileStatement: "DoWhileStatement",
                EmptyStatement: "EmptyStatement",
                ExpressionStatement: "ExpressionStatement",
                ForStatement: "ForStatement",
                ForInStatement: "ForInStatement",
                FunctionDeclaration: "FunctionDeclaration",
                FunctionExpression: "FunctionExpression",
                Identifier: "Identifier",
                IfStatement: "IfStatement",
                Literal: "Literal",
                LabeledStatement: "LabeledStatement",
                LogicalExpression: "LogicalExpression",
                MemberExpression: "MemberExpression",
                NewExpression: "NewExpression",
                ObjectExpression: "ObjectExpression",
                Program: "Program",
                Property: "Property",
                ReturnStatement: "ReturnStatement",
                SequenceExpression: "SequenceExpression",
                SwitchStatement: "SwitchStatement",
                SwitchCase: "SwitchCase",
                ThisExpression: "ThisExpression",
                ThrowStatement: "ThrowStatement",
                TryStatement: "TryStatement",
                UnaryExpression: "UnaryExpression",
                UpdateExpression: "UpdateExpression",
                VariableDeclaration: "VariableDeclaration",
                VariableDeclarator: "VariableDeclarator",
                WhileStatement: "WhileStatement",
                WithStatement: "WithStatement"
            }, isArray = Array.isArray, isArray || (isArray = function(array) {
                return "[object Array]" === Object.prototype.toString.call(array);
            }), VisitorKeys = {
                AssignmentExpression: [ "left", "right" ],
                ArrayExpression: [ "elements" ],
                BlockStatement: [ "body" ],
                BinaryExpression: [ "left", "right" ],
                BreakStatement: [ "label" ],
                CallExpression: [ "callee", "arguments" ],
                CatchClause: [ "param", "body" ],
                ConditionalExpression: [ "test", "consequent", "alternate" ],
                ContinueStatement: [ "label" ],
                DebuggerStatement: [],
                DirectiveStatement: [],
                DoWhileStatement: [ "body", "test" ],
                EmptyStatement: [],
                ExpressionStatement: [ "expression" ],
                ForStatement: [ "init", "test", "update", "body" ],
                ForInStatement: [ "left", "right", "body" ],
                FunctionDeclaration: [ "id", "params", "body" ],
                FunctionExpression: [ "id", "params", "body" ],
                Identifier: [],
                IfStatement: [ "test", "consequent", "alternate" ],
                Literal: [],
                LabeledStatement: [ "label", "body" ],
                LogicalExpression: [ "left", "right" ],
                MemberExpression: [ "object", "property" ],
                NewExpression: [ "callee", "arguments" ],
                ObjectExpression: [ "properties" ],
                Program: [ "body" ],
                Property: [ "key", "value" ],
                ReturnStatement: [ "argument" ],
                SequenceExpression: [ "expressions" ],
                SwitchStatement: [ "discriminant", "cases" ],
                SwitchCase: [ "test", "consequent" ],
                ThisExpression: [],
                ThrowStatement: [ "argument" ],
                TryStatement: [ "block", "handlers", "finalizer" ],
                UnaryExpression: [ "argument" ],
                UpdateExpression: [ "argument" ],
                VariableDeclaration: [ "declarations" ],
                VariableDeclarator: [ "id", "init" ],
                WhileStatement: [ "test", "body" ],
                WithStatement: [ "object", "body" ]
            }, VisitorOption = {
                Break: 1,
                Skip: 2
            }, wrappers = {
                PropertyWrapper: "Property"
            }, exports.version = "0.0.4", exports.Syntax = Syntax, exports.traverse = traverse, 
            exports.replace = replace, exports.VisitorKeys = VisitorKeys, exports.VisitorOption = VisitorOption;
        });
    }), require.define("/tools/entry-point.js", function(require, module, exports, __dirname, __filename, process, global) {
        !function() {
            "use strict";
            var escodegen;
            escodegen = global.escodegen = require("../escodegen"), escodegen.browser = !0;
        }();
    }), require("/tools/entry-point.js");
}();

var asmCrypto = function() {
    function IllegalStateError() {
        var err = Error.apply(this, arguments);
        this.message = err.message, this.stack = err.stack;
    }
    function IllegalArgumentError() {
        var err = Error.apply(this, arguments);
        this.message = err.message, this.stack = err.stack;
    }
    function SecurityError() {
        var err = Error.apply(this, arguments);
        this.message = err.message, this.stack = err.stack;
    }
    function string_to_bytes(str, utf8) {
        utf8 = !!utf8;
        for (var len = str.length, bytes = new Uint8Array(utf8 ? 4 * len : len), i = 0, j = 0; i < len; i++) {
            var c = str.charCodeAt(i);
            if (utf8 && 55296 <= c && c <= 56319) {
                if (++i >= len) throw new Error("Malformed string, low surrogate expected at position " + i);
                c = (55296 ^ c) << 10 | 65536 | 56320 ^ str.charCodeAt(i);
            } else if (!utf8 && c >>> 8) throw new Error("Wide characters are not allowed.");
            !utf8 || c <= 127 ? bytes[j++] = c : c <= 2047 ? (bytes[j++] = 192 | c >> 6, bytes[j++] = 128 | 63 & c) : c <= 65535 ? (bytes[j++] = 224 | c >> 12, 
            bytes[j++] = 128 | c >> 6 & 63, bytes[j++] = 128 | 63 & c) : (bytes[j++] = 240 | c >> 18, 
            bytes[j++] = 128 | c >> 12 & 63, bytes[j++] = 128 | c >> 6 & 63, bytes[j++] = 128 | 63 & c);
        }
        return bytes.subarray(0, j);
    }
    function bytes_to_string(bytes, utf8) {
        utf8 = !!utf8;
        for (var len = bytes.length, chars = new Array(len), i = 0, j = 0; i < len; i++) {
            var b = bytes[i];
            if (!utf8 || b < 128) chars[j++] = b; else if (b >= 192 && b < 224 && i + 1 < len) chars[j++] = (31 & b) << 6 | 63 & bytes[++i]; else if (b >= 224 && b < 240 && i + 2 < len) chars[j++] = (15 & b) << 12 | (63 & bytes[++i]) << 6 | 63 & bytes[++i]; else {
                if (!(b >= 240 && b < 248 && i + 3 < len)) throw new Error("Malformed UTF8 character at byte offset " + i);
                var c = (7 & b) << 18 | (63 & bytes[++i]) << 12 | (63 & bytes[++i]) << 6 | 63 & bytes[++i];
                c <= 65535 ? chars[j++] = c : (c ^= 65536, chars[j++] = 55296 | c >> 10, chars[j++] = 56320 | 1023 & c);
            }
        }
        for (var str = "", bs = 16384, i = 0; i < j; i += bs) str += String.fromCharCode.apply(String, chars.slice(i, i + bs <= j ? i + bs : j));
        return str;
    }
    function bytes_to_hex(arr) {
        for (var str = "", i = 0; i < arr.length; i++) {
            var h = (255 & arr[i]).toString(16);
            h.length < 2 && (str += "0"), str += h;
        }
        return str;
    }
    function bytes_to_base64(arr) {
        return btoa(bytes_to_string(arr));
    }
    function is_string(a) {
        return "string" == typeof a;
    }
    function is_buffer(a) {
        return a instanceof ArrayBuffer;
    }
    function is_bytes(a) {
        return a instanceof Uint8Array;
    }
    function _heap_init(constructor, options) {
        var heap = options.heap, size = heap ? heap.byteLength : options.heapSize || 65536;
        if (4095 & size || size <= 0) throw new Error("heap size must be a positive integer and a multiple of 4096");
        return heap = heap || new constructor(new ArrayBuffer(size));
    }
    function _heap_write(heap, hpos, data, dpos, dlen) {
        var hlen = heap.length - hpos, wlen = hlen < dlen ? hlen : dlen;
        return heap.set(data.subarray(dpos, dpos + wlen), hpos), wlen;
    }
    function hash_reset() {
        return this.result = null, this.pos = 0, this.len = 0, this.asm.reset(), this;
    }
    function hash_process(data) {
        if (null !== this.result) throw new IllegalStateError("state must be reset before processing new data");
        if (is_string(data) && (data = string_to_bytes(data)), is_buffer(data) && (data = new Uint8Array(data)), 
        !is_bytes(data)) throw new TypeError("data isn't of expected type");
        for (var asm = this.asm, heap = this.heap, hpos = this.pos, hlen = this.len, dpos = 0, dlen = data.length, wlen = 0; dlen > 0; ) wlen = _heap_write(heap, hpos + hlen, data, dpos, dlen), 
        hlen += wlen, dpos += wlen, dlen -= wlen, wlen = asm.process(hpos, hlen), hpos += wlen, 
        (hlen -= wlen) || (hpos = 0);
        return this.pos = hpos, this.len = hlen, this;
    }
    function hash_finish() {
        if (null !== this.result) throw new IllegalStateError("state must be reset before processing new data");
        return this.asm.finish(this.pos, this.len, 0), this.result = new Uint8Array(this.HASH_SIZE), 
        this.result.set(this.heap.subarray(0, this.HASH_SIZE)), this.pos = 0, this.len = 0, 
        this;
    }
    function sha256_asm(stdlib, foreign, buffer) {
        "use asm";
        var H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0, TOTAL0 = 0, TOTAL1 = 0;
        var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0, I6 = 0, I7 = 0, O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0, O5 = 0, O6 = 0, O7 = 0;
        var HEAP = new stdlib.Uint8Array(buffer);
        function _core(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15) {
            w0 = w0 | 0;
            w1 = w1 | 0;
            w2 = w2 | 0;
            w3 = w3 | 0;
            w4 = w4 | 0;
            w5 = w5 | 0;
            w6 = w6 | 0;
            w7 = w7 | 0;
            w8 = w8 | 0;
            w9 = w9 | 0;
            w10 = w10 | 0;
            w11 = w11 | 0;
            w12 = w12 | 0;
            w13 = w13 | 0;
            w14 = w14 | 0;
            w15 = w15 | 0;
            var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, t = 0;
            a = H0;
            b = H1;
            c = H2;
            d = H3;
            e = H4;
            f = H5;
            g = H6;
            h = H7;
            t = w0 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x428a2f98 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w1 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x71374491 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w2 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xb5c0fbcf | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w3 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xe9b5dba5 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w4 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x3956c25b | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w5 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x59f111f1 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w6 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x923f82a4 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w7 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xab1c5ed5 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w8 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xd807aa98 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w9 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x12835b01 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w10 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x243185be | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w11 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x550c7dc3 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w12 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x72be5d74 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w13 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x80deb1fe | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w14 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x9bdc06a7 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            t = w15 + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xc19bf174 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w0 = t = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xe49b69c1 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w1 = t = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xefbe4786 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w2 = t = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x0fc19dc6 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w3 = t = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x240ca1cc | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w4 = t = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x2de92c6f | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w5 = t = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x4a7484aa | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w6 = t = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x5cb0a9dc | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w7 = t = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x76f988da | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w8 = t = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x983e5152 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w9 = t = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xa831c66d | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w10 = t = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xb00327c8 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w11 = t = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xbf597fc7 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w12 = t = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xc6e00bf3 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w13 = t = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xd5a79147 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w14 = t = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x06ca6351 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w15 = t = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x14292967 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w0 = t = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x27b70a85 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w1 = t = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x2e1b2138 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w2 = t = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x4d2c6dfc | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w3 = t = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x53380d13 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w4 = t = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x650a7354 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w5 = t = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x766a0abb | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w6 = t = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x81c2c92e | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w7 = t = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x92722c85 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w8 = t = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xa2bfe8a1 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w9 = t = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xa81a664b | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w10 = t = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xc24b8b70 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w11 = t = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xc76c51a3 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w12 = t = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xd192e819 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w13 = t = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xd6990624 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w14 = t = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xf40e3585 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w15 = t = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x106aa070 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w0 = t = (w1 >>> 7 ^ w1 >>> 18 ^ w1 >>> 3 ^ w1 << 25 ^ w1 << 14) + (w14 >>> 17 ^ w14 >>> 19 ^ w14 >>> 10 ^ w14 << 15 ^ w14 << 13) + w0 + w9 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x19a4c116 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w1 = t = (w2 >>> 7 ^ w2 >>> 18 ^ w2 >>> 3 ^ w2 << 25 ^ w2 << 14) + (w15 >>> 17 ^ w15 >>> 19 ^ w15 >>> 10 ^ w15 << 15 ^ w15 << 13) + w1 + w10 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x1e376c08 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w2 = t = (w3 >>> 7 ^ w3 >>> 18 ^ w3 >>> 3 ^ w3 << 25 ^ w3 << 14) + (w0 >>> 17 ^ w0 >>> 19 ^ w0 >>> 10 ^ w0 << 15 ^ w0 << 13) + w2 + w11 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x2748774c | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w3 = t = (w4 >>> 7 ^ w4 >>> 18 ^ w4 >>> 3 ^ w4 << 25 ^ w4 << 14) + (w1 >>> 17 ^ w1 >>> 19 ^ w1 >>> 10 ^ w1 << 15 ^ w1 << 13) + w3 + w12 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x34b0bcb5 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w4 = t = (w5 >>> 7 ^ w5 >>> 18 ^ w5 >>> 3 ^ w5 << 25 ^ w5 << 14) + (w2 >>> 17 ^ w2 >>> 19 ^ w2 >>> 10 ^ w2 << 15 ^ w2 << 13) + w4 + w13 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x391c0cb3 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w5 = t = (w6 >>> 7 ^ w6 >>> 18 ^ w6 >>> 3 ^ w6 << 25 ^ w6 << 14) + (w3 >>> 17 ^ w3 >>> 19 ^ w3 >>> 10 ^ w3 << 15 ^ w3 << 13) + w5 + w14 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x4ed8aa4a | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w6 = t = (w7 >>> 7 ^ w7 >>> 18 ^ w7 >>> 3 ^ w7 << 25 ^ w7 << 14) + (w4 >>> 17 ^ w4 >>> 19 ^ w4 >>> 10 ^ w4 << 15 ^ w4 << 13) + w6 + w15 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x5b9cca4f | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w7 = t = (w8 >>> 7 ^ w8 >>> 18 ^ w8 >>> 3 ^ w8 << 25 ^ w8 << 14) + (w5 >>> 17 ^ w5 >>> 19 ^ w5 >>> 10 ^ w5 << 15 ^ w5 << 13) + w7 + w0 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x682e6ff3 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w8 = t = (w9 >>> 7 ^ w9 >>> 18 ^ w9 >>> 3 ^ w9 << 25 ^ w9 << 14) + (w6 >>> 17 ^ w6 >>> 19 ^ w6 >>> 10 ^ w6 << 15 ^ w6 << 13) + w8 + w1 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x748f82ee | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w9 = t = (w10 >>> 7 ^ w10 >>> 18 ^ w10 >>> 3 ^ w10 << 25 ^ w10 << 14) + (w7 >>> 17 ^ w7 >>> 19 ^ w7 >>> 10 ^ w7 << 15 ^ w7 << 13) + w9 + w2 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x78a5636f | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w10 = t = (w11 >>> 7 ^ w11 >>> 18 ^ w11 >>> 3 ^ w11 << 25 ^ w11 << 14) + (w8 >>> 17 ^ w8 >>> 19 ^ w8 >>> 10 ^ w8 << 15 ^ w8 << 13) + w10 + w3 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x84c87814 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w11 = t = (w12 >>> 7 ^ w12 >>> 18 ^ w12 >>> 3 ^ w12 << 25 ^ w12 << 14) + (w9 >>> 17 ^ w9 >>> 19 ^ w9 >>> 10 ^ w9 << 15 ^ w9 << 13) + w11 + w4 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x8cc70208 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w12 = t = (w13 >>> 7 ^ w13 >>> 18 ^ w13 >>> 3 ^ w13 << 25 ^ w13 << 14) + (w10 >>> 17 ^ w10 >>> 19 ^ w10 >>> 10 ^ w10 << 15 ^ w10 << 13) + w12 + w5 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0x90befffa | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w13 = t = (w14 >>> 7 ^ w14 >>> 18 ^ w14 >>> 3 ^ w14 << 25 ^ w14 << 14) + (w11 >>> 17 ^ w11 >>> 19 ^ w11 >>> 10 ^ w11 << 15 ^ w11 << 13) + w13 + w6 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xa4506ceb | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w14 = t = (w15 >>> 7 ^ w15 >>> 18 ^ w15 >>> 3 ^ w15 << 25 ^ w15 << 14) + (w12 >>> 17 ^ w12 >>> 19 ^ w12 >>> 10 ^ w12 << 15 ^ w12 << 13) + w14 + w7 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xbef9a3f7 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            w15 = t = (w0 >>> 7 ^ w0 >>> 18 ^ w0 >>> 3 ^ w0 << 25 ^ w0 << 14) + (w13 >>> 17 ^ w13 >>> 19 ^ w13 >>> 10 ^ w13 << 15 ^ w13 << 13) + w15 + w8 | 0;
            t = t + h + (e >>> 6 ^ e >>> 11 ^ e >>> 25 ^ e << 26 ^ e << 21 ^ e << 7) + (g ^ e & (f ^ g)) + 0xc67178f2 | 0;
            h = g;
            g = f;
            f = e;
            e = d + t | 0;
            d = c;
            c = b;
            b = a;
            a = t + (b & c ^ d & (b ^ c)) + (b >>> 2 ^ b >>> 13 ^ b >>> 22 ^ b << 30 ^ b << 19 ^ b << 10) | 0;
            H0 = H0 + a | 0;
            H1 = H1 + b | 0;
            H2 = H2 + c | 0;
            H3 = H3 + d | 0;
            H4 = H4 + e | 0;
            H5 = H5 + f | 0;
            H6 = H6 + g | 0;
            H7 = H7 + h | 0;
        }
        function _core_heap(offset) {
            offset = offset | 0;
            _core(HEAP[offset | 0] << 24 | HEAP[offset | 1] << 16 | HEAP[offset | 2] << 8 | HEAP[offset | 3], HEAP[offset | 4] << 24 | HEAP[offset | 5] << 16 | HEAP[offset | 6] << 8 | HEAP[offset | 7], HEAP[offset | 8] << 24 | HEAP[offset | 9] << 16 | HEAP[offset | 10] << 8 | HEAP[offset | 11], HEAP[offset | 12] << 24 | HEAP[offset | 13] << 16 | HEAP[offset | 14] << 8 | HEAP[offset | 15], HEAP[offset | 16] << 24 | HEAP[offset | 17] << 16 | HEAP[offset | 18] << 8 | HEAP[offset | 19], HEAP[offset | 20] << 24 | HEAP[offset | 21] << 16 | HEAP[offset | 22] << 8 | HEAP[offset | 23], HEAP[offset | 24] << 24 | HEAP[offset | 25] << 16 | HEAP[offset | 26] << 8 | HEAP[offset | 27], HEAP[offset | 28] << 24 | HEAP[offset | 29] << 16 | HEAP[offset | 30] << 8 | HEAP[offset | 31], HEAP[offset | 32] << 24 | HEAP[offset | 33] << 16 | HEAP[offset | 34] << 8 | HEAP[offset | 35], HEAP[offset | 36] << 24 | HEAP[offset | 37] << 16 | HEAP[offset | 38] << 8 | HEAP[offset | 39], HEAP[offset | 40] << 24 | HEAP[offset | 41] << 16 | HEAP[offset | 42] << 8 | HEAP[offset | 43], HEAP[offset | 44] << 24 | HEAP[offset | 45] << 16 | HEAP[offset | 46] << 8 | HEAP[offset | 47], HEAP[offset | 48] << 24 | HEAP[offset | 49] << 16 | HEAP[offset | 50] << 8 | HEAP[offset | 51], HEAP[offset | 52] << 24 | HEAP[offset | 53] << 16 | HEAP[offset | 54] << 8 | HEAP[offset | 55], HEAP[offset | 56] << 24 | HEAP[offset | 57] << 16 | HEAP[offset | 58] << 8 | HEAP[offset | 59], HEAP[offset | 60] << 24 | HEAP[offset | 61] << 16 | HEAP[offset | 62] << 8 | HEAP[offset | 63]);
        }
        function _state_to_heap(output) {
            output = output | 0;
            HEAP[output | 0] = H0 >>> 24;
            HEAP[output | 1] = H0 >>> 16 & 255;
            HEAP[output | 2] = H0 >>> 8 & 255;
            HEAP[output | 3] = H0 & 255;
            HEAP[output | 4] = H1 >>> 24;
            HEAP[output | 5] = H1 >>> 16 & 255;
            HEAP[output | 6] = H1 >>> 8 & 255;
            HEAP[output | 7] = H1 & 255;
            HEAP[output | 8] = H2 >>> 24;
            HEAP[output | 9] = H2 >>> 16 & 255;
            HEAP[output | 10] = H2 >>> 8 & 255;
            HEAP[output | 11] = H2 & 255;
            HEAP[output | 12] = H3 >>> 24;
            HEAP[output | 13] = H3 >>> 16 & 255;
            HEAP[output | 14] = H3 >>> 8 & 255;
            HEAP[output | 15] = H3 & 255;
            HEAP[output | 16] = H4 >>> 24;
            HEAP[output | 17] = H4 >>> 16 & 255;
            HEAP[output | 18] = H4 >>> 8 & 255;
            HEAP[output | 19] = H4 & 255;
            HEAP[output | 20] = H5 >>> 24;
            HEAP[output | 21] = H5 >>> 16 & 255;
            HEAP[output | 22] = H5 >>> 8 & 255;
            HEAP[output | 23] = H5 & 255;
            HEAP[output | 24] = H6 >>> 24;
            HEAP[output | 25] = H6 >>> 16 & 255;
            HEAP[output | 26] = H6 >>> 8 & 255;
            HEAP[output | 27] = H6 & 255;
            HEAP[output | 28] = H7 >>> 24;
            HEAP[output | 29] = H7 >>> 16 & 255;
            HEAP[output | 30] = H7 >>> 8 & 255;
            HEAP[output | 31] = H7 & 255;
        }
        function reset() {
            H0 = 0x6a09e667;
            H1 = 0xbb67ae85;
            H2 = 0x3c6ef372;
            H3 = 0xa54ff53a;
            H4 = 0x510e527f;
            H5 = 0x9b05688c;
            H6 = 0x1f83d9ab;
            H7 = 0x5be0cd19;
            TOTAL0 = TOTAL1 = 0;
        }
        function init(h0, h1, h2, h3, h4, h5, h6, h7, total0, total1) {
            h0 = h0 | 0;
            h1 = h1 | 0;
            h2 = h2 | 0;
            h3 = h3 | 0;
            h4 = h4 | 0;
            h5 = h5 | 0;
            h6 = h6 | 0;
            h7 = h7 | 0;
            total0 = total0 | 0;
            total1 = total1 | 0;
            H0 = h0;
            H1 = h1;
            H2 = h2;
            H3 = h3;
            H4 = h4;
            H5 = h5;
            H6 = h6;
            H7 = h7;
            TOTAL0 = total0;
            TOTAL1 = total1;
        }
        function process(offset, length) {
            offset = offset | 0;
            length = length | 0;
            var hashed = 0;
            if (offset & 63) return -1;
            while ((length | 0) >= 64) {
                _core_heap(offset);
                offset = offset + 64 | 0;
                length = length - 64 | 0;
                hashed = hashed + 64 | 0;
            }
            TOTAL0 = TOTAL0 + hashed | 0;
            if (TOTAL0 >>> 0 < hashed >>> 0) TOTAL1 = TOTAL1 + 1 | 0;
            return hashed | 0;
        }
        function finish(offset, length, output) {
            offset = offset | 0;
            length = length | 0;
            output = output | 0;
            var hashed = 0, i = 0;
            if (offset & 63) return -1;
            if (~output) if (output & 31) return -1;
            if ((length | 0) >= 64) {
                hashed = process(offset, length) | 0;
                if ((hashed | 0) == -1) return -1;
                offset = offset + hashed | 0;
                length = length - hashed | 0;
            }
            hashed = hashed + length | 0;
            TOTAL0 = TOTAL0 + length | 0;
            if (TOTAL0 >>> 0 < length >>> 0) TOTAL1 = TOTAL1 + 1 | 0;
            HEAP[offset | length] = 0x80;
            if ((length | 0) >= 56) {
                for (i = length + 1 | 0; (i | 0) < 64; i = i + 1 | 0) HEAP[offset | i] = 0x00;
                _core_heap(offset);
                length = 0;
                HEAP[offset | 0] = 0;
            }
            for (i = length + 1 | 0; (i | 0) < 59; i = i + 1 | 0) HEAP[offset | i] = 0;
            HEAP[offset | 56] = TOTAL1 >>> 21 & 255;
            HEAP[offset | 57] = TOTAL1 >>> 13 & 255;
            HEAP[offset | 58] = TOTAL1 >>> 5 & 255;
            HEAP[offset | 59] = TOTAL1 << 3 & 255 | TOTAL0 >>> 29;
            HEAP[offset | 60] = TOTAL0 >>> 21 & 255;
            HEAP[offset | 61] = TOTAL0 >>> 13 & 255;
            HEAP[offset | 62] = TOTAL0 >>> 5 & 255;
            HEAP[offset | 63] = TOTAL0 << 3 & 255;
            _core_heap(offset);
            if (~output) _state_to_heap(output);
            return hashed | 0;
        }
        function hmac_reset() {
            H0 = I0;
            H1 = I1;
            H2 = I2;
            H3 = I3;
            H4 = I4;
            H5 = I5;
            H6 = I6;
            H7 = I7;
            TOTAL0 = 64;
            TOTAL1 = 0;
        }
        function _hmac_opad() {
            H0 = O0;
            H1 = O1;
            H2 = O2;
            H3 = O3;
            H4 = O4;
            H5 = O5;
            H6 = O6;
            H7 = O7;
            TOTAL0 = 64;
            TOTAL1 = 0;
        }
        function hmac_init(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15) {
            p0 = p0 | 0;
            p1 = p1 | 0;
            p2 = p2 | 0;
            p3 = p3 | 0;
            p4 = p4 | 0;
            p5 = p5 | 0;
            p6 = p6 | 0;
            p7 = p7 | 0;
            p8 = p8 | 0;
            p9 = p9 | 0;
            p10 = p10 | 0;
            p11 = p11 | 0;
            p12 = p12 | 0;
            p13 = p13 | 0;
            p14 = p14 | 0;
            p15 = p15 | 0;
            reset();
            _core(p0 ^ 0x5c5c5c5c, p1 ^ 0x5c5c5c5c, p2 ^ 0x5c5c5c5c, p3 ^ 0x5c5c5c5c, p4 ^ 0x5c5c5c5c, p5 ^ 0x5c5c5c5c, p6 ^ 0x5c5c5c5c, p7 ^ 0x5c5c5c5c, p8 ^ 0x5c5c5c5c, p9 ^ 0x5c5c5c5c, p10 ^ 0x5c5c5c5c, p11 ^ 0x5c5c5c5c, p12 ^ 0x5c5c5c5c, p13 ^ 0x5c5c5c5c, p14 ^ 0x5c5c5c5c, p15 ^ 0x5c5c5c5c);
            O0 = H0;
            O1 = H1;
            O2 = H2;
            O3 = H3;
            O4 = H4;
            O5 = H5;
            O6 = H6;
            O7 = H7;
            reset();
            _core(p0 ^ 0x36363636, p1 ^ 0x36363636, p2 ^ 0x36363636, p3 ^ 0x36363636, p4 ^ 0x36363636, p5 ^ 0x36363636, p6 ^ 0x36363636, p7 ^ 0x36363636, p8 ^ 0x36363636, p9 ^ 0x36363636, p10 ^ 0x36363636, p11 ^ 0x36363636, p12 ^ 0x36363636, p13 ^ 0x36363636, p14 ^ 0x36363636, p15 ^ 0x36363636);
            I0 = H0;
            I1 = H1;
            I2 = H2;
            I3 = H3;
            I4 = H4;
            I5 = H5;
            I6 = H6;
            I7 = H7;
            TOTAL0 = 64;
            TOTAL1 = 0;
        }
        function hmac_finish(offset, length, output) {
            offset = offset | 0;
            length = length | 0;
            output = output | 0;
            var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, hashed = 0;
            if (offset & 63) return -1;
            if (~output) if (output & 31) return -1;
            hashed = finish(offset, length, -1) | 0;
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
            _hmac_opad();
            _core(t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768);
            if (~output) _state_to_heap(output);
            return hashed | 0;
        }
        function pbkdf2_generate_block(offset, length, block, count, output) {
            offset = offset | 0;
            length = length | 0;
            block = block | 0;
            count = count | 0;
            output = output | 0;
            var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0;
            if (offset & 63) return -1;
            if (~output) if (output & 31) return -1;
            HEAP[offset + length | 0] = block >>> 24;
            HEAP[offset + length + 1 | 0] = block >>> 16 & 255;
            HEAP[offset + length + 2 | 0] = block >>> 8 & 255;
            HEAP[offset + length + 3 | 0] = block & 255;
            hmac_finish(offset, length + 4 | 0, -1) | 0;
            h0 = t0 = H0, h1 = t1 = H1, h2 = t2 = H2, h3 = t3 = H3, h4 = t4 = H4, h5 = t5 = H5, 
            h6 = t6 = H6, h7 = t7 = H7;
            count = count - 1 | 0;
            while ((count | 0) > 0) {
                hmac_reset();
                _core(t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768);
                t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
                _hmac_opad();
                _core(t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768);
                t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;
                h0 = h0 ^ H0;
                h1 = h1 ^ H1;
                h2 = h2 ^ H2;
                h3 = h3 ^ H3;
                h4 = h4 ^ H4;
                h5 = h5 ^ H5;
                h6 = h6 ^ H6;
                h7 = h7 ^ H7;
                count = count - 1 | 0;
            }
            H0 = h0;
            H1 = h1;
            H2 = h2;
            H3 = h3;
            H4 = h4;
            H5 = h5;
            H6 = h6;
            H7 = h7;
            if (~output) _state_to_heap(output);
            return 0;
        }
        return {
            reset: reset,
            init: init,
            process: process,
            finish: finish,
            hmac_reset: hmac_reset,
            hmac_init: hmac_init,
            hmac_finish: hmac_finish,
            pbkdf2_generate_block: pbkdf2_generate_block
        };
    }
    function sha256_constructor(options) {
        options = options || {}, this.heap = _heap_init(Uint8Array, options), this.asm = options.asm || sha256_asm(global, null, this.heap.buffer), 
        this.BLOCK_SIZE = _sha256_block_size, this.HASH_SIZE = _sha256_hash_size, this.reset();
    }
    function get_sha256_instance() {
        return null === sha256_instance && (sha256_instance = new sha256_constructor({
            heapSize: 1048576
        })), sha256_instance;
    }
    function sha256_bytes(data) {
        if (void 0 === data) throw new SyntaxError("data required");
        return get_sha256_instance().reset().process(data).finish().result;
    }
    function sha256_hex(data) {
        return bytes_to_hex(sha256_bytes(data));
    }
    function sha256_base64(data) {
        return bytes_to_base64(sha256_bytes(data));
    }
    var exports = {}, global = function() {
        return this;
    }();
    IllegalStateError.prototype = Object.create(Error.prototype, {
        name: {
            value: "IllegalStateError"
        }
    }), IllegalArgumentError.prototype = Object.create(Error.prototype, {
        name: {
            value: "IllegalArgumentError"
        }
    }), SecurityError.prototype = Object.create(Error.prototype, {
        name: {
            value: "SecurityError"
        }
    });
    var _sha256_block_size = (global.Float64Array || global.Float32Array, 64), _sha256_hash_size = 32;
    sha256_constructor.BLOCK_SIZE = _sha256_block_size, sha256_constructor.HASH_SIZE = _sha256_hash_size;
    var sha256_prototype = sha256_constructor.prototype;
    sha256_prototype.reset = hash_reset, sha256_prototype.process = hash_process, sha256_prototype.finish = hash_finish;
    var sha256_instance = null;
    return sha256_constructor.bytes = sha256_bytes, sha256_constructor.hex = sha256_hex, 
    sha256_constructor.base64 = sha256_base64, exports.SHA256 = sha256_constructor, 
    "function" == typeof define && define.amd ? define([], function() {
        return exports;
    }) : "object" == typeof module && module.exports ? module.exports = exports : global.asmCrypto = exports, 
    exports;
}(), TCellPolicyCache = function() {
    var exports = {
        version: 1
    }, localStorageCacheLabel = "tcell_agent_policy_cache";
    return exports.getCachedPolicy = function() {
        try {
            var cachedPolicyStr = localStorage.getItem(localStorageCacheLabel), cachedPolicy = JSON.parse(cachedPolicyStr);
            return cachedPolicy.result ? cachedPolicy.result : cachedPolicy;
        } catch (err) {
            return null;
        }
    }, exports.setCachedPolicyString = function(policyStr) {
        if (policyStr) try {
            localStorage.setItem(localStorageCacheLabel, policyStr);
        } catch (err) {
            console.log("Error setting policy ", err);
        }
    }, exports;
}(), TCellApi = function() {
    function addTCellHeaders(xhr, apiKey) {
        xhr.setRequestHeader("Authorization", "Bearer " + apiKey), xhr.setRequestHeader("TCellAgent", "JSAgent " + TCELL_AGENT_VERSION);
    }
    function populateConfigFromCache(config) {
        populateConfigFromResponseConfig(config, TCellPolicyCache.getCachedPolicy());
    }
    function populateConfigFromResponseConfig(config, responseConfig) {
        responseConfig && (responseConfig.clickjacking_iframe_url && (config.clickjacking_iframe_url = responseConfig.clickjacking_iframe_url), 
        responseConfig.security_token && (config.security_token = responseConfig.security_token), 
        responseConfig.post_url && (config.post_url = responseConfig.post_url), responseConfig.override_config && (config.override_config = responseConfig.override_config), 
        responseConfig.script_signature_whitelist && (config.script_signature_whitelist = responseConfig.script_signature_whitelist), 
        responseConfig.enable_csp_session_match_frame && (config.enable_csp_session_match_frame = responseConfig.enable_csp_session_match_frame));
    }
    function fetchConfigFromUrl(baseUrl, appId, apiKey, sessionId, contextId, response_callback) {
        if (null != appId && null != apiKey && null != baseUrl) {
            var configUrl = baseUrl + "/app/" + encodeURIComponent(appId) + "/jsconfig?session_id=" + encodeURIComponent(sessionId);
            contextId && (configUrl = configUrl + "&context_id=" + encodeURIComponent(contextId));
            var apiHash = TCellUtils.hashFunction(apiKey);
            if (configUrl = configUrl + "&ah=" + encodeURIComponent(apiHash)) {
                var configXhr = new TCellSafeguards.xhrConstructor();
                TCellSafeguards.xhrOpen.call(configXhr, "GET", configUrl, !0), addTCellHeaders(configXhr, apiKey), 
                configXhr.ontimeout = function() {
                    return console.error("tCellAgent: config timeout!"), response_callback(null);
                }, configXhr.onreadystatechange = function() {
                    if (4 == configXhr.readyState && 200 == configXhr.status) try {
                        return responseConfig = TCellSafeguards.parse(configXhr.responseText), TCellPolicyCache.setCachedPolicyString(configXhr.responseText), 
                        responseConfig.result ? void response_callback(responseConfig.result) : response_callback(responseConfig);
                    } catch (err) {
                        return console.error("tCellAgent: error parsing response: " + err), response_callback(null);
                    } else if (4 == configXhr.readyState) return console.error("tCellAgent: config request failed!"), 
                    response_callback(null);
                }, configXhr.timeout = TIMEOUT, TCellSafeguards.xhrSend.call(configXhr);
            } else console.error("JSAgent: Failed to send via XHR. URL not configured"), response_callback(null);
        }
    }
    var TCELL_AGENT_VERSION = "0.2.9", TCELL_API_BASE_URL = "https://api.tcell.io/api/v1", TIMEOUT = 4500, loadConfig = function(config, baseUrl, appId, apiKey, sessionId, contextId, callbackAfterLoad) {
        baseUrl = baseUrl || TCELL_API_BASE_URL, config.application_id = appId, config.api_key = apiKey, 
        config.context_id = contextId, fetchConfigFromUrl(baseUrl, appId, apiKey, sessionId, contextId, function(responseConfig) {
            populateConfigFromResponseConfig(config, responseConfig), callbackAfterLoad && callbackAfterLoad();
        });
    };
    return {
        version: 1,
        sendJSEvents: function(config, events, response_callback) {
            if (!config || null == config.post_url) return void response_callback(!1);
            var xhr = new TCellSafeguards.xhrConstructor(), message = TCellSafeguards.stringify({
                application_id: config.application_id,
                request_id: config.request_id,
                session_id: config.session_id,
                events: events
            });
            TCellSafeguards.xhrOpen.call(xhr, "POST", config.post_url, !0), xhr.setRequestHeader("Content-type", "application/json; charset=utf-8"), 
            addTCellHeaders(xhr, config.api_key), xhr.onreadystatechange = function() {
                4 == xhr.readyState && (200 == xhr.status ? response_callback && response_callback(!0) : (console.log("failed to send events"), 
                console.log(TCellSafeguards.stringify(TCellSafeguards.parse(message), null, 2)), 
                response_callback && response_callback(!1)));
            }, TCellSafeguards.xhrSend.call(xhr, message);
        },
        loadConfig: loadConfig,
        populateConfigFromCache: populateConfigFromCache
    };
}(), hexcase = 0, b64pad = "=", sha256_K = new Array(1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998), TCellSafeguards = {
    initRun: !1,
    stringify: null,
    parse: null,
    xhrSend: null,
    xhrOpen: null,
    xhrConstructor: null,
    init: function() {
        if (!0 !== TCellSafeguards.initRun) {
            TCellSafeguards.initRun = !0;
            var originalStringify = JSON.stringify;
            TCellSafeguards.stringify = function() {
                var object_toJson = Object.prototype.toJSON, array_toJson = Array.prototype.toJSON, date_toJson = Date.prototype.toJSON, string_toJson = String.prototype.toJSON;
                delete Object.prototype.toJSON, delete Array.prototype.toJSON, delete Date.prototype.toJSON, 
                delete String.prototype.toJSON;
                var returnValue = originalStringify.apply(self, arguments);
                return object_toJson && (Object.prototype.toJSON = object_toJson), array_toJson && (Array.prototype.toJSON = array_toJson), 
                string_toJson && (String.prototype.toJSON = string_toJson), date_toJson && (Date.prototype.toJSON = date_toJson), 
                returnValue;
            };
            var originalParse = JSON.parse;
            TCellSafeguards.parse = function() {
                return originalParse.apply(self, arguments);
            }, TCellSafeguards.xhrConstructor = XMLHttpRequest.prototype.constructor, TCellSafeguards.xhrOpen = XMLHttpRequest.prototype.open, 
            TCellSafeguards.xhrSend = XMLHttpRequest.prototype.send;
        }
    }
}, TCellUtils = {
    getThisScriptTag: function() {
        try {
            if (null != document.currentScript && '<script type="text/javascript">\n    window.__karma__.loaded();\n  <\/script>' !== document.currentScript.outerHTML) return document.currentScript;
        } catch (err) {
            console.log("currentScript not supported, attempting dom");
        }
        var scripts = document.getElementsByTagName("script"), tcell_script_tag = scripts[scripts.length - 1];
        return null != tcell_script_tag.getAttribute("tcellappid") ? tcell_script_tag : (tcell_script_tag = document.getElementById("tcellAgent"), 
        null != tcell_script_tag ? tcell_script_tag : null);
    },
    hashFunction: function(stringToHash) {
        var i, chr, len, hash = 0;
        if (0 == stringToHash.length) return "tc1-" + hash;
        for (i = 0, len = stringToHash.length; i < len; i++) chr = stringToHash.charCodeAt(i), 
        hash = (hash << 5) - hash + chr, hash |= 0;
        return "tc1-" + stringToHash.length.toString(32) + hash.toString(32);
    },
    sha256HashFunction: function(stringToHash) {
        if (stringToHash.length > 750) try {
            return "sha256-" + asmCrypto.SHA256.base64(stringToHash);
        } catch (err) {
            TCellUtils.hideFullExceptionMessage || console.log(err);
        }
        try {
            return "sha256-" + b64_sha256(stringToHash);
        } catch (err) {
            console.log("sha256 failed"), console.log(err);
        }
        return "sha256-sha256failed";
    },
    urlSafeSHA: function(stringToHash) {
        return this.sha256HashFunction(stringToHash).replace(/\+/g, "-").replace(/\//g, "_");
    },
    guid: function() {
        function s4() {
            return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1);
        }
        return function() {
            return s4() + s4() + "-" + s4() + "-" + s4() + "-" + s4() + "-" + s4() + s4() + s4();
        };
    }(),
    inIframe: function() {
        try {
            return window.self !== window.top;
        } catch (e) {
            return !0;
        }
    },
    getElementXPath: function(element) {
        return element && element.id ? '//*[@id="' + element.id + '"]' : TCellUtils.getElementTreeXPath(element);
    },
    getAttributeXPath: function(attrName, element) {
        return void 0 !== attrName ? TCellUtils.getElementTreeXPath(element) + "[@" + attrName + "]" : TCellUtils.getElementTreeXPath(element);
    },
    getElementTreeXPath: function(element) {
        for (var paths = []; element && 1 == element.nodeType; element = element.parentNode) {
            for (var index = 0, sibling = element.previousSibling; sibling; sibling = sibling.previousSibling) sibling.nodeType != Node.DOCUMENT_TYPE_NODE && sibling.nodeName == element.nodeName && ++index;
            var tagName = element.nodeName.toLowerCase(), pathIndex = index ? "[" + (index + 1) + "]" : "";
            paths.splice(0, 0, tagName + pathIndex);
        }
        return paths.length ? "/" + paths.join("/") : null;
    },
    getStackTrace: function() {
        var retVal = void 0;
        try {
            throw new Error();
        } catch (e) {
            retVal = e.stack;
        }
        return retVal;
    },
    getScrubbedContext: function(targetElement) {
        if (null == targetElement || !(targetElement instanceof HTMLElement)) return [];
        var whitelist = [ "id", "class", "name" ], scrubNode = function(node) {
            for (var scrubbedNode = {
                n: node.tagName
            }, i = 0; i < node.attributes.length; i++) {
                var name = node.attributes[i].name;
                -1 !== whitelist.indexOf(name) ? scrubbedNode[name] = node.attributes[i].value : (void 0 == scrubbedNode.other && (scrubbedNode.other = []), 
                scrubbedNode.other.push(name));
            }
            return scrubbedNode;
        }, scrubbedInjectedNode = scrubNode(targetElement.cloneNode(!1)), scrubbedParentNode = null;
        targetElement.parentElement && (scrubbedParentNode = scrubNode(targetElement.parentElement.cloneNode(!1)));
        for (var before = [], nodeStep = targetElement, i = 0; i < 2 && (nodeStep = nodeStep.previousElementSibling); i++) {
            var nodeStepScrubbed = scrubNode(nodeStep.cloneNode(!1));
            before.unshift(nodeStepScrubbed);
        }
        var after = [];
        nodeStep = targetElement;
        for (var j = 0; j < 2 && (nodeStep = nodeStep.nextElementSibling); j++) nodeStepScrubbed = scrubNode(nodeStep.cloneNode(!1)), 
        after.push(nodeStepScrubbed);
        return [ scrubbedInjectedNode, scrubbedParentNode, before, after ];
    }
}, TCellOverride = function() {
    function isFunction(x) {
        return "[object Function]" == Object.prototype.toString.call(x);
    }
    function stackTrace() {
        var err = new Error(), st = err.stack;
        if (!st) return "STNULL";
        var sta = st.split("\n"), line_source = sta[2].split("@")[1];
        return void 0 == line_source && (3 == sta.length && "" === sta[2] ? line_source = sta[1].split("@")[1] : (line_source = sta[3].trim().split(" "), 
        line_source = line_source[line_source.length - 1], line_source.startsWith("(") && (line_source = line_source.substring(1, line_source.length - 1)))), 
        line_source;
    }
    function replaceProperty(label, block, log_cb) {
        for (var functions = overrides[label], i = 0; i < functions.length; i++) {
            var parent = functions[i].parent, property_str = functions[i].property_str;
            (log_cb || block) && function() {
                var proxied = parent[property_str], back_to_native = !1;
                parent.__defineGetter__(property_str, function() {
                    if (1 == back_to_native) return null;
                    var stack_trace = stackTrace();
                    if ("native" == String(stack_trace)) return back_to_native = !0, null;
                    if (log_cb) {
                        var currentScript = document.currentScript, dynamic_hash = null;
                        if (currentScript) try {
                            var sigprocesssor = new ScriptSignatureProcessor();
                            dynamic_hash = TCellUtils.sha256HashFunction(sigprocesssor.computeScriptTemplateData(currentScript.text).template);
                        } catch (err) {}
                        log_cb(property_str, stack_trace, dynamic_hash), console.debug("Property " + property_str + " caught being accessed. " + stack_trace + " tag " + document.currentScript);
                    }
                    return block ? isFunction(proxied) ? function() {} : null : proxied;
                });
            }();
        }
    }
    var exports = {
        version: 1,
        author: "garrett@tcell.io"
    }, overrides = {
        cookie: [ {
            parent: document,
            property_str: "cookie"
        } ],
        "document.write": [ {
            parent: document,
            property_str: "write"
        } ],
        createElement: [ {
            parent: document,
            property_str: "createElement"
        } ],
        getElementById: [ {
            parent: document,
            property_str: "getElementById"
        } ],
        querySelector: [ {
            parent: document,
            property_str: "querySelector"
        } ],
        querySelectorAll: [ {
            parent: document,
            property_str: "querySelectorAll"
        } ],
        documentElement: [ {
            parent: document,
            property_str: "documentElement"
        } ],
        fromCharCode: [ {
            parent: window.String,
            property_str: "fromCharCode"
        } ],
        alert: [ {
            parent: window,
            property_str: "alert"
        } ],
        prompt: [ {
            parent: window,
            property_str: "prompt"
        } ],
        confirm: [ {
            parent: window,
            property_str: "confirm"
        } ],
        unescape: [ {
            parent: window,
            property_str: "unescape"
        } ],
        eval: [ {
            parent: window,
            property_str: "eval"
        } ],
        Function: [ {
            parent: window,
            property_str: "Function"
        } ],
        XMLHttpRequest: [ {
            parent: window,
            property_str: "XMLHttpRequest"
        } ]
    };
    return "undefined" != typeof Window && overrides.alert.push({
        parent: Window.prototype,
        property_str: "alert"
    }), exports.stackTrace = stackTrace, exports.replaceProperty = replaceProperty, 
    exports;
}(), TCELL_SIGNATURES = {
    STATIC_SIGNATURE: "static",
    TEMPLATE_SIGNATURE: "template"
}, attribNames = [ "src", "href", "onafterprint", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange", "onload", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate", "onresize", "onstorage", "onblur", "onchange", "oncontextmenu", "onfocus", "oninput", "oninvalid", "onreset", "onsearch", "onselect", "onsubmit", "onfocusin", "onkeydown", "onkeypress", "onkeyup", "onclick", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "onmousedown", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onscroll", "onwheel", "oncopy", "oncut", "onpaste", "onabort", "oncanplay", "oncanplaythrough", "oncuechange", "ondurationchange", "onemptied", "onended", "onerror", "onloadeddata", "onloadedmetadata", "onloadstart", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked", "onseeking", "onstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "onshow", "ontoggle" ];

ScriptSignatureProcessor.prototype = {
    start: function(script_signature_whitelist) {
        if (script_signature_whitelist || (script_signature_whitelist = {}, script_signature_whitelist[TCELL_SIGNATURES.STATIC_SIGNATURE] = [], 
        script_signature_whitelist[TCELL_SIGNATURES.TEMPLATE_SIGNATURE] = []), this.script_signature_whitelist = script_signature_whitelist, 
        !0 !== this.is_ready) {
            this.is_ready = !0;
            for (var elementData, i = 0; i < this.scriptElementQueue.length; i++) elementData = this.scriptElementQueue[i], 
            this.processScriptElement(elementData.scriptElement, elementData.scriptString, elementData.scriptPos, elementData.scriptCxt);
            this.scriptElementQueue = [];
            for (var j = 0; j < this.attributesQueue.length; j++) elementData = this.attributesQueue[j], 
            this.processAttribute(elementData.scriptElement, elementData.attr, elementData.attrValue, elementData.attrName, elementData.scriptPos, elementData.scriptCxt);
            this.attributesQueue = [];
            for (var k = 0; k < this.scriptStringQueue.length; k++) elementData = this.scriptStringQueue[k], 
            this.processScriptString(elementData.scriptElement, elementData.scriptString, elementData.altPos, elementData.scriptPos, elementData.scriptCxt);
            this.scriptStringQueue = [];
        }
    },
    queueScriptElement: function(scriptElement, scriptString, scriptPos, scriptCxt) {
        this.scriptElementQueue.push({
            scriptElement: scriptElement,
            scriptString: scriptString,
            scriptPos: scriptPos,
            scriptCxt: scriptCxt
        });
    },
    queueScriptString: function(scriptElement, scriptString, altPos, scriptPos, scriptCxt) {
        this.scriptStringQueue.push({
            scriptElement: scriptElement,
            scriptString: scriptString,
            altPos: altPos,
            scriptPos: scriptPos,
            scriptCxt: scriptCxt
        });
    },
    queueAttribute: function(scriptElement, attr, attrValue, attrName, scriptPos, scriptCxt) {
        this.attributesQueue.push({
            scriptElement: scriptElement,
            attr: attr,
            attrValue: attrValue,
            attrName: attrName,
            scriptPos: scriptPos,
            scriptCxt: scriptCxt
        });
    },
    processCandidateElement: function(element) {
        try {
            for (var aIndex = 0; aIndex < element.attributes.length; aIndex++) {
                var attr = element.attributes[aIndex];
                attr.specified && -1 != this.attribNames.indexOf(attr.name) && this.processAttribute(element, attr);
            }
        } catch (err) {
            console.log(err);
        }
    },
    processAttribsWithScripts: function() {
        try {
            for (var qString = "", i = 0; i < this.attribNames.length; i++) qString += "[" + this.attribNames[i] + "],";
            qString = qString.substr(0, qString.length - 1);
            for (var candidateElements = document.querySelectorAll(qString), eIndex = 0; eIndex < candidateElements.length; eIndex++) {
                var element = candidateElements[eIndex];
                this.processCandidateElement(element);
            }
        } catch (err) {
            console.log(err);
        }
    },
    decodeHtml: function(html) {
        return this.javascriptPrefixDecodeElement.innerHTML = html, this.javascriptPrefixDecodeElement.value;
    },
    scriptIfJavaScriptProtocol: function(value) {
        if (value && value.length > this.javascriptPrefixLength && -1 !== [ "j", "J", "&" ].indexOf(value[0])) {
            console.log("A");
            var decoded = this.decodeHtml(value);
            if (decoded) {
                var colonIdx = decoded.indexOf(":");
                if (-1 !== colonIdx) {
                    var prefix = decoded.substring(0, colonIdx + 1).replace(/\s+/g, ""), payload = decoded.substring(colonIdx + 1, decoded.length);
                    if (console.log(prefix), console.log(payload), "javascript:" === prefix.toLowerCase()) return payload;
                }
            }
        }
        return null;
    },
    processAttribute: function(scriptElement, attr, scriptTxt, attrName, scriptPos, scriptCxt) {
        try {
            if (!attr || !attr.value || "" == attr.value) return;
            -1 !== [ "src", "href" ].indexOf(attr.name) ? ("src" === attr.name && "IFRAME" === scriptElement.nodeName || "href" === attr.name && "A" === scriptElement.nodeName) && null !== (scriptTxt = this.scriptIfJavaScriptProtocol(attr.value)) && this.processAttributeNotSrc(scriptElement, attr, scriptTxt, attrName, scriptPos, scriptCxt) : (scriptTxt = this.scriptIfJavaScriptProtocol(attr.value) || scriptTxt, 
            this.processAttributeNotSrc(scriptElement, attr, scriptTxt, attrName, scriptPos, scriptCxt));
        } catch (err) {
            console.log(err);
        }
    },
    processAttributeNotSrc: function(scriptElement, attr, scriptTxt, attrName, scriptPos, scriptCxt) {
        try {
            if (!this.is_ready) return void this.queueAttribute(scriptElement, attr, attr.value, attr.name, this.getScriptPosition(scriptElement, attr.name), this.getScriptContext(scriptElement));
            if (!scriptTxt && (scriptTxt = attr.value, !this.scriptTextIsRunnable(scriptTxt))) return;
            attrName || (attrName = attr.name);
            var staticCheck = this.checkStatic(scriptTxt);
            if (0 == staticCheck.ok) {
                var templateCheck = this.checkTemplate(scriptTxt);
                0 == templateCheck.ok && (scriptPos || (scriptPos = this.getScriptPosition(scriptElement, attrName)), 
                scriptCxt || (scriptCxt = this.getScriptContext(scriptElement)), this.reportScriptViolation(scriptElement, scriptTxt, staticCheck.details, templateCheck.details, scriptPos, scriptCxt));
            }
        } catch (err) {
            console.log(err);
        }
    },
    processScriptElement: function(scriptElement, scriptText, scriptPos, scriptCxt) {
        try {
            if (this.scriptElementIsRunnable(scriptElement)) {
                if (!this.is_ready) return void this.queueScriptElement(scriptElement, scriptElement.innerHTML, this.getScriptPosition(scriptElement), this.getScriptContext(scriptElement));
                scriptText || (scriptText = scriptElement.innerHTML);
                var staticCheck = this.checkStatic(scriptText);
                if (0 == staticCheck.ok) {
                    var templateCheck = this.checkTemplate(scriptText);
                    0 == templateCheck.ok && (scriptPos || (scriptPos = this.getScriptPosition(scriptElement)), 
                    scriptCxt || (scriptCxt = this.getScriptContext(scriptElement)), this.reportScriptViolation(scriptElement, scriptText, staticCheck.details, templateCheck.details, scriptPos, scriptCxt));
                }
            }
        } catch (err) {
            console.log(err);
        }
    },
    processScriptString: function(scriptElement, scriptString, altLocation, scriptPos, scriptCxt) {
        try {
            if (!this.is_ready) {
                var preScriptPos = null;
                return preScriptPos = null == scriptElement ? altLocation : this.getScriptPosition(scriptElement), 
                void this.queueScriptString(scriptElement, scriptString, altLocation, preScriptPos, this.getScriptContext(scriptElement));
            }
            var staticCheck = this.checkStatic(scriptString);
            if (0 == staticCheck.ok) {
                var templateCheck = this.checkTemplate(scriptString);
                0 == templateCheck.ok && (scriptCxt || (scriptCxt = this.getScriptContext(scriptElement)), 
                scriptPos = this.getScriptPosition(scriptElement), this.reportScriptViolation(scriptElement, scriptString, staticCheck.details, templateCheck.details, scriptPos));
            }
        } catch (err) {
            console.log(err);
        }
    },
    checkStatic: function(scriptText) {
        var retVal = {
            ok: !1,
            details: {}
        }, hash = this.computeHash(scriptText);
        retVal.details = {
            type: TCELL_SIGNATURES.STATIC_SIGNATURE,
            hash: hash,
            script: scriptText
        };
        var signatures = this.script_signature_whitelist[TCELL_SIGNATURES.STATIC_SIGNATURE];
        return signatures && -1 != signatures.indexOf(hash) && (retVal.ok = !0), retVal;
    },
    computeHash: function(text) {
        return TCellUtils.urlSafeSHA(text);
    },
    checkTemplate: function(scriptText) {
        var retVal = {
            ok: !1,
            details: {}
        }, templateData = this.computeScriptTemplateData(scriptText), scriptTemplate = templateData.template, scriptHash = this.computeHash(scriptTemplate);
        retVal.details = {
            type: TCELL_SIGNATURES.TEMPLATE_SIGNATURE,
            hash: scriptHash,
            methodCounts: templateData.methodCounts,
            template: scriptTemplate,
            script: scriptText
        };
        var signatures = this.script_signature_whitelist[TCELL_SIGNATURES.TEMPLATE_SIGNATURE];
        return signatures && -1 != signatures.indexOf(scriptHash) && (retVal.ok = !0), retVal;
    },
    computeScriptTemplateData: function(script) {
        var retVal = "";
        try {
            var parserConf = {
                tolerant: !0,
                templateAll: !0,
                methodsToCount: [ "alert", "window.alert", "prompt", "window.prompt", "confirm" ]
            }, program = esprima.parse(script, parserConf);
            retVal = {
                template: escodegen.generate(program),
                methodCounts: program.methodCounts
            };
        } catch (e) {
            console.debug(e);
        }
        return retVal;
    },
    scriptTextIsRunnable: function(scriptText) {
        var retVal = !0;
        return retVal = retVal && scriptText.length > 2;
    },
    scriptElementIsRunnable: function(scriptElement) {
        var retVal = !0;
        retVal = retVal && this.scriptTextIsRunnable(scriptElement.innerHTML), retVal = retVal && "" === scriptElement.src;
        var executeableTypes = [ "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript" ];
        return retVal = retVal && ("" === scriptElement.type || -1 != executeableTypes.indexOf(scriptElement.type));
    },
    getScriptContext: function(scriptElement) {
        if (scriptElement instanceof HTMLElement) try {
            return TCellUtils.getScrubbedContext(scriptElement);
        } catch (err) {}
        return null;
    },
    getScriptPosition: function(scriptElement, attrName) {
        var retVal = {};
        retVal.loc = TCellUtils.getAttributeXPath(attrName, scriptElement);
        var headNodes = document.head.childNodes, headIndex = Array.prototype.indexOf.call(headNodes, scriptElement);
        if (-1 !== headIndex) retVal.script_index = headIndex, retVal.last_index = headNodes.length - 1; else {
            var bodyNodes = document.body.childNodes, bodyIndex = Array.prototype.indexOf.call(bodyNodes, scriptElement);
            -1 !== bodyIndex && (retVal.script_index = bodyIndex, retVal.last_index = bodyNodes.length - 1);
        }
        return retVal;
    },
    reportScriptViolation: function(scriptElement, scriptText, staticDetails, templateDetails, scriptPos, scriptCxt) {
        this.report_callback(scriptElement, scriptText, staticDetails, templateDetails, scriptPos, scriptCxt);
    }
};

var TCellSession = function() {
    var requestId, sessionId, exports = {
        version: 1
    }, localStorageSessionIdLabel = "tcell_agent_session_id";
    return exports.getRequestId = function() {
        return requestId || (requestId = exports.generateRequestId()), requestId;
    }, exports.getSessionId = function() {
        return sessionId || (sessionId = localStorage.getItem(localStorageSessionIdLabel)) || (sessionId = exports.generateSessionId(), 
        localStorage.setItem(localStorageSessionIdLabel, sessionId)), sessionId;
    }, exports.generateSessionId = function() {
        return TCellUtils.guid();
    }, exports.generateRequestId = function() {
        return (4095 * Math.random() << 0).toString(16) + ":" + (65535 * Math.random() << 0).toString(16) + ":" + (65535 * Math.random() << 0).toString(16) + ":" + (65535 * Math.random() << 0).toString(16);
    }, exports.getRequestIdPrefix = function() {
        return "b";
    }, exports;
}(), TCellAgent = function(old_static_config) {
    var exports = {}, VIOLATION_REPORT_VERSION = "0.4", scriptSigProcessor = null, cancel_flag = !1, loaded = !1, config = {
        session_id: TCellSession.getSessionId(),
        request_id: TCellSession.getRequestId(),
        securitytoken: "securitytoken",
        application_id: "app_id",
        apikey: "api_key",
        post_url: null,
        script_signature_whitelist: [],
        override_config: [ {
            label: "alert",
            block: !1,
            log: !0
        } ],
        send_timeout: 2e3,
        active_protection: !0,
        url_whitelist: {},
        test_mode: !1,
        enable_csp_session_match_frame: !1
    };
    if (exports.config = config, old_static_config) for (var attrname in old_static_config) config[attrname] = old_static_config[attrname]; else TCellApi.populateConfigFromCache(config);
    scriptSigProcessor = new ScriptSignatureProcessor(function(scriptElement, scriptText, staticDetails, templateDetails, scriptPos, scriptCxt) {
        console.error("Found script that violates the security policy. static-hash=" + staticDetails.hash + ", template-hash=" + templateDetails.hash + ", pos = " + TCellSafeguards.stringify(scriptPos) + ', template="' + templateDetails.template + '", script=: ' + scriptText + ", methodCounts = " + templateDetails.methodCounts), 
        scriptCxt && console.error("scriptCxt: " + TCellSafeguards.stringify(scriptCxt));
        var event = createEvent("inline_script");
        event.data.static_hash = staticDetails.hash, event.data.template_hash = templateDetails.hash, 
        event.data.template = templateDetails.template, event.data.script_pos = scriptPos, 
        event.data.methodCounts = templateDetails.methodCounts, event.data.script_cxt = scriptCxt, 
        -1 !== event.data.template.indexOf("var s0") && -1 !== event.data.template.indexOf("var s1") && -1 !== event.data.template.indexOf("dwr.engine._remoteHandleCallback") ? console.debug('Skipping script "' + event.data.template + '"') : /window.script\d+ = '?'/.test(event.data.template) ? console.debug('Skipping script "' + event.data.template + '"') : queueEvent(event);
    }), exports.scriptSigProcessor = scriptSigProcessor;
    var triggerTestCSPViolation = function() {
        var config_xhr = new XMLHttpRequest(), tracking_url = "https://[100::" + TCellSession.getRequestIdPrefix() + config.request_id + "]:50001/this_is_an_intentional_fake_csp_violation_please_ignore";
        config_xhr.open("HEAD", tracking_url, !0), config_xhr.send(null);
    }, handleClickjackingIframeIndicator = function() {
        var clickjacking_url = config.clickjacking_iframe_url;
        if (clickjacking_url) {
            var framingUrl = window.location != window.parent.location ? document.referrer : document.location, currentUrl = document.location.href, documentUri = document.location.protocol + "//" + document.location.host, iframe = document.createElement("iframe");
            iframe.src = clickjacking_url + "?documentUri=" + encodeURIComponent(documentUri) + "&iframe=" + encodeURIComponent(framingUrl) + "&currentUrl=", 
            encodeURIComponent(currentUrl), iframe.frameBorder = 0, iframe.width = "0px", iframe.height = "0px", 
            iframe.tabIndex = "-1", iframe.style.display = "none";
            try {
                document.body.appendChild(iframe);
            } catch (err) {
                try {
                    document.documentElement.appendChild(iframe);
                } catch (err2) {
                    throw new Error("tCell iframe could not be appended to this page.");
                }
            }
        }
    }, encodeURIIfNeeded = function(documentURI) {
        if (documentURI) return encodeURI(decodeURI(documentURI));
    };
    exports.encodeURIIfNeeded = encodeURIIfNeeded;
    var createEvent = function(eventType) {
        var event = {};
        return event.event_type = eventType, event.report_version = VIOLATION_REPORT_VERSION, 
        event.data = {}, event.data.document_uri = encodeURIIfNeeded(document.documentURI), 
        event.data.document_uri || (event.data.document_uri = encodeURIIfNeeded(document.location.href)), 
        event.data.referrer = document.referrer, event;
    };
    exports.createEvent = createEvent;
    var eventQueue = [], queueEvent = function(event) {
        eventQueue.push(event);
    }, flushEvents = function() {
        if (!0 !== cancel_flag && eventQueue.length > 0) {
            if (config.post_url) try {
                TCellApi.sendJSEvents(config, eventQueue);
            } catch (err) {
                console.log("JSAgent: Failed to send via XHR."), console.log(err), eventQueue = [];
            } else console.log("JSAgent: Failed to send via XHR. URL not configured");
            eventQueue = [];
        }
    };
    exports.flushEvents = flushEvents;
    var clearEvents = function() {
        eventQueue = [];
    };
    exports.clearEvents = clearEvents;
    var postPageSummary = function() {
        var psevent = createEvent("page_summary");
        psevent.data.num_scripts = document.scripts.length, psevent.data.in_iframe = TCellUtils.inIframe(), 
        queueEvent(psevent);
    };
    exports.postPageSummary = postPageSummary;
    var scanNode = function(node) {
        if ("SCRIPT" == node.nodeName && scriptSigProcessor.processScriptElement(node), 
        node.attributes) for (var i = 0; i < node.attributes.length; i++) {
            var attr = node.attributes[i];
            attr && attr.specified && (-1 != scriptSigProcessor.attribNames.indexOf(attr.name) || attr.name && -1 !== [ "onload" ].indexOf(attr.name.toLowerCase()) && null === node[attr.name]) && scriptSigProcessor.processAttribute(node, attr);
        }
        if (node.childNodes) for (var j = 0; j < node.childNodes.length; j++) scanNode(node.childNodes[j]);
    };
    exports.scanNode = scanNode;
    var watchDOM = function() {
        new (window.MutationObserver || window.WebKitMutationObserver)(function(mutations) {
            if (!0 !== cancel_flag) for (var i = 0; i < mutations.length; i++) if ("childList" == mutations[i].type) for (var j = 0; j < mutations[i].addedNodes.length; j++) {
                var addedNode = mutations[i].addedNodes[j];
                scanNode(addedNode);
            } else if ("attributes" == mutations[i].type) {
                var element = mutations[i].target, attr = element.attributes[mutations[i].attributeName];
                attr && -1 != scriptSigProcessor.attribNames.indexOf(mutations[i].attributeName) && scriptSigProcessor.processAttribute(element, attr);
            }
        }).observe(document, {
            subtree: !0,
            attributes: !0,
            childList: !0,
            characterData: !0,
            attributeOldValue: !0,
            characterDataOldValue: !0
        });
    };
    exports.watchDOM = watchDOM;
    var scanDOM = function() {
        var flush = flushEvents;
        document.addEventListener("DOMContentLoaded", function(event) {
            if (!0 !== loaded && !0 !== cancel_flag) {
                for (var scriptElements = document.getElementsByTagName("script"), i = 0; i < scriptElements.length; i++) scriptSigProcessor.processScriptElement(scriptElements[i]);
                scriptSigProcessor.processAttribsWithScripts();
                flush(), loaded = !0, watchDOM();
            }
        });
    }, wrapEvalTypeMethods = function() {
        var OldFunction = Function;
        Function = function() {
            var createdFunction = OldFunction.apply(this, arguments);
            return !1 === cancel_flag && scriptSigProcessor.processScriptString(document.currentScript, createdFunction.toString(), "Function"), 
            createdFunction;
        }, Function.prototype = OldFunction.prototype;
    }, doMethodOverrides = function() {
        if (config.override_config) for (var handle_override_log = function(property_str, stack_trace, template_hash) {
            var js_property_violation_event = createEvent("js_property_violation");
            js_property_violation_event.data.stack_trace = stack_trace, js_property_violation_event.data.property_str = property_str, 
            js_property_violation_event.data.template_hash = template_hash, queueEvent(js_property_violation_event);
        }, i = 0; i < config.override_config.length; i++) {
            var override_data = config.override_config[i];
            TCellOverride.replaceProperty(override_data.label, override_data.block && config.active_protection, override_data.log ? handle_override_log : null);
        }
    }, safeguardCriticalFunctions = function() {
        TCellSafeguards.init();
    }, run = function(static_config) {
        if (safeguardCriticalFunctions(), static_config) for (var attrname in static_config) config[attrname] = static_config[attrname];
        !0 === config.enable_csp_session_match_frame && triggerTestCSPViolation(), wrapEvalTypeMethods(), 
        scanDOM(), doMethodOverrides(), static_config && postConfigRun();
    };
    exports.run = run;
    var postConfigRun = function() {
        postPageSummary(), handleClickjackingIframeIndicator(), setInterval(flushEvents, 500);
    }, cancel = function() {
        cancel_flag = !0;
    };
    exports.cancel = cancel;
    var loadConfig = function() {
        safeguardCriticalFunctions();
        var thisScriptTag = TCellUtils.getThisScriptTag();
        if (null == thisScriptTag) return exports;
        var session_id, scriptTagAppId = thisScriptTag.getAttribute("tcellappid"), scriptTagAppApiKey = thisScriptTag.getAttribute("tcellapikey"), scriptTagAppContextId = thisScriptTag.getAttribute("tcellcontextid"), scriptTagBaseUrl = thisScriptTag.getAttribute("tcellbaseurl"), scriptTagMode = thisScriptTag.getAttribute("mode");
        session_id = "test" === scriptTagMode ? "test_session_id" : config.session_id;
        try {
            TCellApi.loadConfig(config, scriptTagBaseUrl, scriptTagAppId, scriptTagAppApiKey, session_id, scriptTagAppContextId, function() {
                postConfigRun(), scriptSigProcessor && scriptSigProcessor.start(config.script_signature_whitelist);
            });
        } catch (err) {
            scriptSigProcessor && scriptSigProcessor.start(config.script_signature_whitelist);
        }
        return exports;
    };
    return exports.loadConfig = loadConfig, exports;
};

window && ("Microsoft Internet Explorer" == navigator.appName || ("undefined" != typeof tcell_config && tcell_config ? (tcell_config.override = !0, 
TCellAgent().run(tcell_config), delete tcell_config) : TCellAgent().loadConfig().run()));