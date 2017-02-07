# SublimeEncodingUtils  Sublime Text 3 Package
A useful multitool for programmers. The general idea is to convert selected characters from 
any of the categories below to another.

- Entropy calculation (Shannon entropy)
- Password strength calculation
- Unix timestamp to datetime
- Encoding: Base64
- Hash: Md5, Sha256, Sha512
- Cipher: ROT13
- Numeric Code Refence (NCR)
- Hexadecimal / Decimal
- Unicode Hexadecimal representation
- HTML entities
- CSS (e.g. unicode characters)
- XML entities
- URL encoding
- JSON format strings
- Regular Expression escape
- SQL 'LIKE' escape

# Add Repository to sublime
To add a repository using Package Control press ctrl+shift+p (Win, Linux) or cmd+shift+p (OS X). 
Type Add Repository, enter the URL  https://github.com/CodedK/SublimeEncodingUtils. 

# Installation
Using Package Control, press ctrl+shift+p, type "install package" and then "EncodingUtils".

# Commands
`base64_decode` : Encode into base64

`base64_encode` : Decode from base64

`check_ord` : Returns the ordinal of a character

`dec_hex` : Converts from decimal to hexademical

`dencr` : Converts Numeric Code Reference to characters

`escape_like` : Escapes SQL-LIKE meta characters

`escape_regex` : Escapes regex meta-characters

`hex_dec` : Converts hexademical to decimal

`hex_unicode` : Converts HEX representation to the respective unicode character

`html_deentitize` : Converts HTML entities to a character

`html_entitize` : Converts characters to their HTML entity

`json_escape` : Escapes a string and surrounds it in quotes, according to the JSON encoding.

`json_unescape` : Unescapes a string (include the quotes!) according to JSON format encoding.

`md5_encode` : Returns md5 hash from the selected string

`panos_ncr` : Converts characters to their Numeric Code Reference (NCR)

`panos_rot` : Encodes string using caesar ROT13 cipher

`safe_html_deentitize` : Converts HTML entities to a character, but preserves HTML reserved characters

`safe_html_entitize` : Converts characters to their HTML entity, but preserves HTML reserved characters

`sha256_encode` : Returns sha256 hash from the selected string

`sha512_encode` : Returns sha512 hash from the selected string

`shannon` : Computes Shannon entropy

`strength` : Password strength calculator. Outputs Shannon entropy based on charactrer set used.

`string_encode_paste` : Uses the clipboard as input and converts to the desired encoding

`unicode_hex` : Converts unicode characters to their HEX representation

`unixstamp` : Converts Unix timestamps to datetime

`url_decode` : Converts escaped URL characters

`url_encode` : Escapes special URL characters (urllib.quote). 
	
	`old_school` argument (default: `true`) will return `+` instead of `%20` when encoding spaces.

`xml_deentitize` : Converts XML entities to a character

`xml_entitize` : Converts characters to their XML entity


Usage
-----
Access commands via:

- Right-click menu item `EncodingUtils`
- Menu item `Edit -> EncodingUtils`
- Several keyboard shortcuts:
  - Check Default (Windows).sublime-keymap, Default (OSX).sublime-keymap

 # by Panos Kalatzantonakis
 MIT Licence
