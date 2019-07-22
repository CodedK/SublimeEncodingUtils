# Getting Started

![examples](res://Packages/SublimeEncodingUtils/assets/sl_menu.png){: width=624px, height=456px }

Sublime Encoding Utils is a plugin that provides useful string conversion and generation utilities.
<br><br>

The general idea is to convert selected characters from any of the categories below to another category.

- Calculate ***CIPHER***: `ROT13`
- Calculate ***Hash***: `Md5`, `Sha256`, `Sha512`
- Calculate ***Password strength***
- Calculate character ***Entropy*** (Shannon entropy)
- Convert ***unicode*** characters to their ***Hexadecimal*** representation and vice versa
- Convert ***unix timestamp*** to ***datetime*** and vice versa
- Convert characters to their ***HTML entities*** and vice versa
- Convert characters to their ***Numeric Code Refence*** `NCR`
- Convert characters to their ***XML entities*** and vice versa
- Encoding: `Base64`, `Morse`, `URL Encoding`
- Escape / Un-Escape ***JSON*** format strings
- Escape / Un-Escape ***Regular Expression***
- Escape / Un-Escape ***SQL statements***
- Fix files with ***wrong encoding*** (ÄïêéìÞ ÅëëçíéêÜ  <kbd>↷</kbd> Δοκιμή Ελληνικά)
- Hexadecimal / Decimal


<br><br>
# Usage
When you are all setup, you can run the commands below.  You can execute commands from the command palette, or directly from the main or context menu:

- Right-click menu item `EncodingUtils`
- Menu item `Edit -> EncodingUtils`
- Several keyboard shortcuts (check keymaps):
	- Default (Windows).sublime-keymap
	- Default (OSX).sublime-keymap

<br><br>
# Commands
`base64_decode` : Encode into base64

`base64_encode` : Decode from base64

`check_ord` : Returns the ordinal of a character

`dec_hex` : Converts from decimal to hexademical

`dencr` : Converts Numeric Code Reference to characters

`entropy` : Computes Shannon entropy

`escape_like` : Escapes SQL-LIKE meta characters

`escape_regex` : Escapes regex meta-characters

`fix_wrong_encoding` : Fixes wrongly encoded Greek characters

`generate_uuid` : Generate RFC compliant UUID

`hex_dec` : Converts hexademical to decimal

`hex_unicode` : Converts HEX representation to the respective unicode character

`html_deentitize` : Converts HTML entities to a character

`html_entitize` : Converts characters to their HTML entity

`json_escape` : Escapes a string and surrounds it in quotes, according to the JSON encoding.

`json_unescape` : Unescapes a string (include the quotes!) according to JSON format encoding.

`md5_encode` : Returns md5 hash from the selected string

`morse_me` : Encode ascii string to Morse

`panos_ncr` : Converts characters to their Numeric Code Reference (NCR)

`panos_rot` : Encodes string using caesar ROT13 cipher

`safe_html_deentitize` : Converts HTML entities to a character, but preserves HTML reserved characters

`safe_html_entitize` : Converts characters to their HTML entity, but preserves HTML reserved characters

`sha256_encode` : Returns sha256 hash from the selected string

`sha512_encode` : Returns sha512 hash from the selected string

`strength` : Password strength calculator. Outputs Shannon entropy based on charactrer set used.

`string_encode_paste` : Uses the clipboard as input and converts to the desired encoding

`unicode_hex` : Converts unicode characters to their HEX representation

`unixstamp` : Converts Unix timestamps to datetime and vice versa

`url_decode` : Converts escaped URL characters

`url_encode` : Escapes special URL characters (urllib.quote).

	`old_school` argument (default: `true`) will return `+` instead of `%20` when encoding spaces.

`xml_deentitize` : Converts XML entities to a character

`xml_entitize` : Converts characters to their XML entity


<br><br>
# How to Use in a Plugin

To help developers who plan to tap into Sublime Encoding Utils, the documentation provides some [examples](https://github.com/CodedK/SublimeEncodingUtils).

<br><br>
 by Panos Kalatzantonakis
 MIT Licence
