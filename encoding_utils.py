# coding: utf8
import base64
import codecs
import hashlib
import json
import math
import re
import string
import sys

import sublime

import sublime_plugin


try:
    from .encodingutils.escape_table import (
        html_escape_table,
        html5_escape_table,
        html_reserved_list,
        xml_escape_table
    )
except ValueError:
    from encodingutils.escape_table import (
        html5_escape_table,
        html_escape_table,
        html_reserved_list,
        xml_escape_table
    )

try:
    import urllib.parse
    quote_plus = urllib.parse.quote_plus
    unquote_plus = urllib.parse.unquote_plus
except ImportError:
    import urllib

    def quote_plus(text):
        return urllib.quote_plus(text.encode('utf8'))

    def unquote_plus(text):
        return urllib.unquote_plus(text.encode('utf8'))


try:
    unichr(32)
except NameError:
    def unichr(val):
        return chr(val)


class StringEncodePaste(sublime_plugin.WindowCommand):
    def run(self, **kwargs):
        items = [
            ('Base64 Decode', 'base64_decode'),
            ('Base64 Encode', 'base64_encode'),
            ('Css Escape', 'css_escape'),
            ('Css Unescape', 'css_unescape'),
            ('Dec Hex', 'dec_hex'),
            ('Encode to Morse', 'morse_me'),
            ('Escape Like', 'escape_like'),
            ('Escape Regex', 'escape_regex'),
            ('Fix Wrong Encoding', 'fix_wrong_encoding'),
            ('Hex Dec', 'hex_dec'),
            ('Hex Unicode', 'hex_unicode'),
            ('Html Deentitize', 'html_deentitize'),
            ('Html Entitize', 'html_entitize'),
            ('Json Escape', 'json_escape'),
            ('Json Unescape', 'json_unescape'),
            ('Md5 Encode', 'md5_encode'),
            ('NCR Decode', 'dencr'),
            ('NCR Encode', 'panos_ncr'),
            ('Password Strength', 'strength'),
            ('Safe Html Deentitize', 'safe_html_deentitize'),
            ('Safe Html Entitize', 'safe_html_entitize'),
            ('Sha256 Encode', 'sha256_encode'),
            ('Sha512 Encode', 'sha512_encode'),
            ('Sha512 Encode', 'sha512_encode'),
            ('Shannon Entropy', 'entropy'),
            ('Unicode Hex', 'unicode_hex'),
            ('Unixtime to datetime', 'unixstamp'),
            ('Url Decode', 'url_decode'),
            ('Url Encode', 'url_encode'),
            ('Xml Deentitize', 'xml_deentitize'),
            ('Xml Entitize', 'xml_entitize'),
        ]

        lines = list(map(lambda line: line[0], items))
        commands = list(map(lambda line: line[1], items))
        view = self.window.active_view()
        if not view:
            return

        def on_done(item):
            if item == -1:
                return
            view.run_command(commands[item], {'source': 'clipboard'})

        self.window.show_quick_panel(lines, on_done)


class StringEncode(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        regions = self.view.sel()

        if kwargs.get('source') == 'clipboard':
            del kwargs['source']
            text = sublime.get_clipboard()
            replacement = self.encode(text, **kwargs)
            for region in regions:
                if region.empty():
                    self.view.insert(edit, region.begin(), replacement)
                else:
                    self.view.replace(edit, region, replacement)
            return

        elif 'source' in kwargs:
            sublime.status_message('Unsupported source {0!r}'.format(kwargs['source']))
            return

        if any(map(lambda region: region.empty(), regions)):
            regions = [sublime.Region(0, self.view.size())]
        for region in regions:
            text = self.view.substr(region)
            replacement = self.encode(text, **kwargs)
            self.view.replace(edit, region, replacement)


class UnixstampCommand(StringEncode):
    def encode(self, text):
        import datetime
        ret = ''
        try:
            if len(text) > 10:
                ret = datetime.datetime.fromtimestamp(float(text)).strftime('%d-%m-%Y %H:%M:%S:%f')
            else:
                ret = datetime.datetime.fromtimestamp(int(text)).strftime('%d-%m-%Y %H:%M:%S')
        except:
            try:
                ret = datetime.datetime.strptime(str(text), "%d-%m-%Y %H:%M:%S")
                ret = str(int(ret.timestamp()))
            except:
                ret = text
        return ret


class EntropyCommand(StringEncode):
    def encode(self, text):
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = str(- sum([p * math.log(p) / math.log(2.0) for p in prob]))
        entropy = entropy
        return entropy


class IdealEntropyCommand(StringEncode):
    def encode(self, text):
        length = len(text)
        prob = 1.0 / length
        ret = str(-1.0 * length * prob * math.log(prob) / math.log(2.0))
        return ret


class MorseMeCommand(StringEncode):
    def encode(self, text):
        char_code_map = {
            "a": ".-",
            "b": "-...",
            "c": "-.-.",
            "d": "-..",
            "e": ".",
            "f": "..-.",
            "g": "--.",
            "h": "....",
            "i": "..",
            "j": ".---",
            "k": "-.-",
            "l": ".-..",
            "m": "--",
            "n": "-.",
            "o": "---",
            "p": ".--.",
            "q": "--.-",
            "r": ".-.",
            "s": "...",
            "t": "-",
            # "": "..-",
            "v": "...-",
            "w": ".--",
            "x": "-..-",
            "y": "-.--",
            "z": "--..",
            " ": " ",
            "1": ".----",
            "2": "..---",
            "3": "...--",
            "4": "....-",
            "5": ".....",
            "6": "-....",
            "7": "--...",
            "8": "---..",
            "9": "----.",
            "0": "-----",
            ".": ".-.-.-",
            ",": "--..--",
            "?": "..--..",
            "'": ".----.",
            "/": "-..-.",
            "(": "-.--.",
            ")": "-.--.-",
            "&": ".-...",
            ":": "---...",
            ";": "-.-.-.",
            "=": "-...-",
            "+": ".-.-.",
            "-": "-....-",
            "_": "..--.-",
            "\"": ".-..-.",
            "$": "...-..-",
            "!": "-.-.--",
            "@": ".--.-."
        }
        ret = ''
        for k in char_code_map:
            if k in text:
                zpp = char_code_map[k]
                # ret = ret + '(' + v + ' | ' + k + ')'
                ret = ret + zpp + ' '
        return ret


class StrengthCommand(StringEncode):
    def encode(self, text):

        def read_str(psw):
            self.numeric = re.compile(r'\d')
            self.loweralpha = re.compile(r'[a-z]')
            self.upperalpha = re.compile(r'[A-Z]')
            # self.symbols = re.compile('[-_.:,;<>?"#$%&/()!@~]')
            self.symbols = re.compile(r'[-!~`@#$%^&*()_+=/?>.<,;:"]')
            self.extended = re.compile('[^\x00-r\x7F]+')
            self.num_of_symbols = 20  # adjust accordingly...
            from math import log, pow
            charset = 0
            if self.numeric.search(psw):
                charset += 10
            if self.loweralpha.search(psw):
                charset += 26
            if self.upperalpha.search(psw):
                charset += 26
            if self.symbols.search(psw):
                charset += self.num_of_symbols
            if self.extended.search(psw):
                charset = 255
            if charset != 0:
                str_entropy = str(float(log(pow(charset, len(psw)), 2)))
            else:
                if len(psw) > 0:
                    # a symbol thats not defined
                    str_entropy = str(float(log(pow(255, len(psw)), 2)))
            return str_entropy
        ret = 0
        ret = str(read_str(text))
        return ret


class CheckOrdCommand(StringEncode):
    def encode(self, text):
        ret = ''
        for c in text[:]:
            ret += str(ord(c)) + '.'
        return ret


class PanosRotCommand(StringEncode):
    def encode(self, text):
        return codecs.encode(text, 'rot_13')


class PanosNcrCommand(StringEncode):
    def encode(self, text):
        ret = ''
        for c in text[:]:
            ret += '&#' + str(ord(c)) + ';'
            # if ord(c) > 127:
            #     ret += '&#' + str(ord(c)) + ';'
            # else:
            #     ret += c
        return ret


class DencrCommand(StringEncode):
    def encode(self, text):
        while re.search('&#[0-9]+;', text):
            match = re.search('&#([0-9]+);', text)
            text = text.replace(match.group(0), unichr(int(match.group(1), 10)))
        text = text.replace('&amp;', '&')
        return text


class DehcrCommand(StringEncode):
    def encode(self, text):
        while re.search('&#0?[xΧ][0-9a-fA-F]+;', text):
            # &#x395;
            match = re.search('&#0?[xΧ]([0-9a-fA-F]+);', text)
            text = text.replace(match.group(0), unichr(int(match.group(1), 16)))
            # text = text.replace(match.group(0), unichr(int(match.group(1), 10)))
        text = text.replace('&amp;', '&')
        return text


class PanosHcrCommand(StringEncode):
    def encode(self, text):
        ret = ''
        for c in text[:]:
            # if ord(c) > 127:
                ret += '&#' + str(hex(ord(c))) + ';'
            # else:
                # ret += c
        return ret


class FixWrongEncodingCommand(StringEncode):
    # def run(self, view):
    #     self.view = view
    #     # Prompt user for password
    #     message = "Create a Password:"
    #     view.window().show_input_panel(message, "", self.on_done, None, None)
    def run(self, text):
        global my_text

        for region in self.view.sel():
            my_text = self.view.substr(region)
            # self.view.replace(my_text, region, 'replacement') # den douleyei
            # self.view.run_command('insert_snippet', {'contents': my_text})  # DOULEYEI
            # self.view.show_popup(text, max_width=200, on_hide=self.done)

        # #### Enas tropos epilogis olokliris tis grammis
        # currentposition = self.view.sel()[0].begin()
        # currentline = self.view.full_line(currentposition)
        # my_sel = self.view.substr(currentline)
        # self.view.show_popup('The Text other line:' + my_sel, max_width=200, on_hide=self.done)

        # window = sublime.active_window()
        # window.run_command('hide_panel')

        self.check_first()
        # print('User sent:', ret)
        # 'something' is the default message
        # self.view.window().show_input_panel("Please select the correct encoding:", 'iso-8859-7', self.on_done(text, text), None, None)

    def done(self):
        print("finished")


    def check_first(self):
        # ÄïêéìÞ ÅëëçíéêÜ

        # window.show_input_panel('Search For 2:', '', self.on_done, None, None)
        items = ['iso-8859-7', '-', 'iso-8859-1', 'iso-8859-2', 'iso-8859-3', 'iso-8859-4', 'iso-8859-5', 'iso-8859-6', 'iso-8859-7', 'iso-8859-8', 'iso-8859-9', 'iso-8859-10']
        # self.view.show_popup_menu(items, self.on_done)
        self.view.window().show_quick_panel(items=items,
                                            selected_index=8,
                                            # on_select=lambda x: print("s:%i" % x), on_highlight=lambda x: print("h:%i" % x)
                                            on_select=self.on_done
                                            )
        # self.view.show_popup('The Text other line', max_width=100, on_hide=self.on_done(edit))

    def on_done(self, result):
        # print(self.window.active_view().sel())
        # regions = self.view.sel()
        # mytext = self.view.substr(regions)
        # self.view.show_popup(result)
        def_enc = 'iso-8859-7'
        if result == 0:
            def_enc = 'iso-8859-7'
        if result == 2:
            def_enc = 'iso-8859-1'
        if result == 3:
            def_enc = 'iso-8859-2'
        if result == 4:
            def_enc = 'iso-8859-3'
        if result == 5:
            def_enc = 'iso-8859-4'
        if result == 6:
            def_enc = 'iso-8859-5'
        if result == 7:
            def_enc = 'iso-8859-6'
        if result == 8:
            def_enc = 'iso-8859-7'
        if result == 9:
            def_enc = 'iso-8859-8'
        if result == 10:
            def_enc = 'iso-8859-9'
        if result == 11:
            def_enc = 'iso-8859-10'
        ret = ''
        print("Selected value:" + str(result))
        try:
            if result != -1:
                for c in my_text[:]:
                    ret += c.encode('iso-8859-1').decode(def_enc)
                self.view.run_command('insert_snippet', {'contents': ret})  # DOULEYEI
                # self.view.show_popup('Hello, <b>World!</b><br><a href="moo">Click Me</a>', on_navigate=print)
        except Exception as e:
            self.view.show_popup('Wrong encoding selected, <b>(' + def_enc + ')</b>!<br><br>Error: ' + str(e), on_navigate=print)

    # def on_done(self, password):
    #     # self.view.run_command("encode", {"password": password})

    #     # def encode(self, text):
    #     #     ret = ''
    #     #     for c in text[:]:
    #     #         ret += c.encode('iso-8859-1').decode('iso-8859-7')
    #     #     return ret
    #     #     # 'something' is the default message
    #     #     # self.view.window().show_input_panel("Please select the correct encoding:", 'iso-8859-7', self.on_done(text, text), None, None)


class HtmlEntitizeCommand(StringEncode):

    def encode(self, text):
        text = text.replace('&', '&amp;')
        for k in html_escape_table:
            v = html_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for c in text[:]:
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class HtmlDeentitizeCommand(StringEncode):

    def encode(self, text):
        for k in html_escape_table:
            v = html_escape_table[k]
            text = text.replace(v, k)
        for k in html5_escape_table:
            v = html5_escape_table[k]
            text = text.replace(v, k)
        while re.search('&#[xX][a-fA-F0-9]+;', text):
            match = re.search('&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(
                match.group(0), unichr(int('0x' + match.group(1), 16)))
        text = text.replace('&amp;', '&')
        return text


class CssEscapeCommand(StringEncode):

    def encode(self, text):
        ret = ''
        for c in text[:]:
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '\\')
            else:
                ret += c
        return ret


class CssUnescapeCommand(StringEncode):

    def encode(self, text):
        while re.search(r'\\[a-fA-F0-9]+', text):
            match = re.search(r'\\([a-fA-F0-9]+)', text)
            text = text.replace(
                match.group(0), unichr(int('0x' + match.group(1), 16)))
        return text


class SafeHtmlEntitizeCommand(StringEncode):

    def encode(self, text):
        for k in html_escape_table:
            # skip HTML reserved characters
            if k in html_reserved_list:
                continue
            v = html_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for c in text[:]:
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class SafeHtmlDeentitizeCommand(StringEncode):

    def encode(self, text):
        for k in html_escape_table:
            # skip HTML reserved characters
            if k in html_reserved_list:
                continue
            v = html_escape_table[k]
            text = text.replace(v, k)
        while re.search('&#[xX][a-fA-F0-9]+;', text):
            match = re.search('&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(
                match.group(0), unichr(int('0x' + match.group(1), 16)))
        text = text.replace('&amp;', '&')
        return text


class XmlEntitizeCommand(StringEncode):

    def encode(self, text):
        text = text.replace('&', '&amp;')
        for k in xml_escape_table:
            v = xml_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for c in text[:]:
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class XmlDeentitizeCommand(StringEncode):

    def encode(self, text):
        for k in xml_escape_table:
            v = xml_escape_table[k]
            text = text.replace(v, k)
        text = text.replace('&amp;', '&')
        return text


class JsonEscapeCommand(StringEncode):

    def encode(self, text):
        return json.dumps(text)


class JsonUnescapeCommand(StringEncode):

    def encode(self, text):
        return json.loads(text)


class UrlEncodeCommand(StringEncode):

    def encode(self, text, old_school=True):
        quoted = quote_plus(text)
        if old_school:
            return quoted.replace("+", "%20")
        return quoted


class UrlDecodeCommand(StringEncode):

    def encode(self, text):
        return unquote_plus(text)


class Base64EncodeCommand(StringEncode):

    def encode(self, text):
        return base64.b64encode(text.encode('raw_unicode_escape')).decode('ascii')


class Base64DecodeCommand(StringEncode):

    def encode(self, text):
        return base64.b64decode(text).decode('raw_unicode_escape')


class Md5EncodeCommand(StringEncode):

    def encode(self, text):
        hasher = hashlib.md5()
        hasher.update(bytes(text, 'utf-8'))
        return hasher.hexdigest()


class Sha256EncodeCommand(StringEncode):

    def encode(self, text):
        hasher = hashlib.sha256()
        hasher.update(bytes(text, 'utf-8'))
        return hasher.hexdigest()


class Sha1EncodeCommand(StringEncode):

    def encode(self, text):
        hasher = hashlib.sha1()
        hasher.update(bytes(text, 'utf-8'))
        return hasher.hexdigest()


class Sha512EncodeCommand(StringEncode):

    def encode(self, text):
        hasher = hashlib.sha512()
        hasher.update(bytes(text, 'utf-8'))
        return hasher.hexdigest()


class Escaper(StringEncode):

    def encode(self, text):
        return re.sub(r'(?<!\\)(%s)' % self.meta, r'\\\1', text)


class EscapeRegexCommand(Escaper):
    meta = r'[\\*.+^$()\[\]\{\}]'


class EscapeLikeCommand(Escaper):
    meta = r'[%_]'


class HexDecCommand(StringEncode):

    def encode(self, text):
        return str(int(text, 16))


class DecHexCommand(StringEncode):

    def encode(self, text):
        return hex(int(text))


class UnicodeHexCommand(StringEncode):

    def encode(self, text):
        hex_text = u''
        text_bytes = bytes(text, 'utf-16')

        if text_bytes[0:2] == b'\xff\xfe':
            endian = 'little'
            text_bytes = text_bytes[2:]
        elif text_bytes[0:2] == b'\xfe\xff':
            endian = 'big'
            text_bytes = text_bytes[2:]

        char_index = 0
        for c in text_bytes:
            if char_index == 0:
                c1 = c
                char_index += 1
            elif char_index == 1:
                c2 = c
                if endian == 'little':
                    c1, c2 = c2, c1
                tmp = (c1 << 8) + c2
                if tmp < 0x80:
                    hex_text += chr(tmp)
                    char_index = 0
                elif tmp >= 0xd800 and tmp <= 0xdbff:
                    char_index += 1
                else:
                    hex_text += '\\u' + '{0:04x}'.format(tmp)
                    char_index = 0
            elif char_index == 2:
                c3 = c
                char_index += 1
            elif char_index == 3:
                c4 = c
                if endian == 'little':
                    c3, c4 = c4, c3
                tmp1 = ((c1 << 8) + c2) - 0xd800
                tmp2 = ((c3 << 8) + c4) - 0xdc00
                tmp = (tmp1 * 0x400) + tmp2 + 0x10000
                hex_text += '\\U' + '{0:08x}'.format(tmp)
                char_index = 0
        return hex_text


class HexUnicodeCommand(StringEncode):

    def encode(self, text):
        uni_text = text

        endian = sys.byteorder

        r = re.compile(r'\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            first_byte = int(rr.group(1), 16)

            if first_byte >= 0xd8 and first_byte <= 0xdf:
                # Surrogate pair
                pass
            else:
                if endian == 'little':
                    b1 = int(rr.group(2), 16)
                    b2 = int(rr.group(1), 16)
                else:
                    b1 = int(rr.group(1), 16)
                    b2 = int(rr.group(2), 16)

                ch = bytes([b1, b2]).decode('utf-16')

                uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text, rr.start(0) + 1)

        # Surrogate pair (2 bytes + 2 bytes)
        r = re.compile(
            r'\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            if endian == 'little':
                b1 = int(rr.group(2), 16)
                b2 = int(rr.group(1), 16)
                b3 = int(rr.group(4), 16)
                b4 = int(rr.group(3), 16)
            else:
                b1 = int(rr.group(1), 16)
                b2 = int(rr.group(2), 16)
                b3 = int(rr.group(3), 16)
                b4 = int(rr.group(4), 16)

            ch = bytes([b1, b2, b3, b4]).decode('utf-16')

            uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text)

        # Surrogate pair (4 bytes)
        r = re.compile(
            r'\\U([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            tmp = (int(rr.group(1), 16) << 24) \
                + (int(rr.group(2), 16) << 16) \
                + (int(rr.group(3), 16) << 8) \
                + (int(rr.group(4), 16))

            if tmp <= 0xffff:
                ch = chr(tmp)
            else:
                tmp -= 0x10000
                c1 = 0xd800 + int(tmp / 0x400)
                c2 = 0xdc00 + int(tmp % 0x400)
                if endian == 'little':
                    b1 = c1 & 0xff
                    b2 = c1 >> 8
                    b3 = c2 & 0xff
                    b4 = c2 >> 8
                else:
                    b1 = c1 >> 8
                    b2 = c1 & 0xff
                    b3 = c2 >> 8
                    b4 = c2 & 0xff

                ch = bytes([b1, b2, b3, b4]).decode('utf-16')

            uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text)

        return uni_text
