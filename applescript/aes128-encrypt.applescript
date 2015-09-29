(*

aes128-encrypt.applescript

single block AES-128 encryption for AppleScript

Richard Godbee <richard@godbee.net> / 2013-06-03

Usage: osascript aes128-encrypt.applescript <plaintext in hex> <key in hex>

*)

property hexchars : {{"0", 0}, {"1", 1}, {"2", 2}, {"3", 3}, {"4", 4}, {"5", 5}, {"6", 6}, {"7", 7}, {"8", 8}, {"9", 9}, {"a", 10}, {"b", 11}, {"c", 12}, {"d", 13}, {"e", 14}, {"f", 15}}

on galoisMult(a, b)
	if class of a is not integer or class of b is not integer or a is not greater than or equal to 0 or a is not less than or equal to 255 then
		error "galoisMult(a, b): a and b must be integers in the interval [0, 255]"
	end if
	
	if b is equal to 2 then
		return item (a + 1) of {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229}
	else if b is equal to 3 then
		return item (a + 1) of {0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26}
	else
		error "galoisMult(a, b): b must be 2 or 3"
	end if
end galoisMult

on hexToList(s)
	if class of s is not string or (length of s) mod 2 is not equal to 0 then
		error "hexToList(s): s must be a string with an even number of characters"
	end if
	
	local found, i, j, output
	
	set output to {}
	
	repeat with i from 1 to length of s
		set found to false
		
		repeat with j in hexchars
			if (character i of s) is equal to the first item of j then
				set found to true
				
				if i mod 2 is equal to 1 then
					set output to output & (the last item of j)
				else
					set the last item of output to (the last item of output) * 16 + (the last item of j)
				end if
			end if
		end repeat
		
		if not found then
			error "hexToList(s): all characters in s must be hexadecimal digits"
		end if
	end repeat
	
	return output
end hexToList

on listToHex(l)
	if class of l is not list then
		error "listToHex(l): l must be a list of integers"
	end if
	
	local c, nibble, output
	
	set output to ""
	
	repeat with c in l
		if c is not greater than or equal to 0 or c is not less than or equal to 255 then
			error "listToHex(l): integers in l must be in the interval [0, 255]"
		end if
		
		repeat with nibble in {(c div (2 ^ 4)) as integer, (c mod (2 ^ 4)) as integer}
			set output to output & the first item of (item (nibble + 1) of hexchars)
		end repeat
	end repeat
	
	return output
end listToHex

on xor(a, b)
	if class of a is not integer or class of b is not integer or a is not greater than or equal to 0 or b is not greater than or equal to 0 then
		error "xor(a, b): a and b must be integers greater than or equal to 0"
	end if
	
	local a_, b_, i, output
	
	set output to 0
	
	-- integers in AppleScript are 30 bits (including the sign bit), not 32 bits...
	repeat with i from 0 to 28
		set a_ to (a mod (2 ^ (i + 1))) div (2 ^ i)
		set b_ to (b mod (2 ^ (i + 1))) div (2 ^ i)
		
		if a_ is not equal to b_ then
			set output to output + (2 ^ i)
		end if
	end repeat
	
	-- the exponentiation operator in AppleScript returns a real, even if both of its operands are integers...
	return output as integer
end xor

on AddRoundKey(state, roundkey)
	if class of state is not list or class of roundkey is not list or length of state is not 16 or length of roundkey is not 16 then
		error "AddRoundKey(state, roundkey): state and roundkey must be lists of 16 integers"
	end if
	
	local i, new_state
	
	repeat with i in state
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "AddRoundKey(state, roundkey): integers in state must be in the interval [0, 255]"
		end if
	end repeat
	
	repeat with i in roundkey
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "AddRoundKey(state, roundkey): integers in roundkey must be in the interval [0, 255]"
		end if
	end repeat
	
	set new_state to {}
	
	repeat with i from 1 to 16
		set new_state to new_state & xor(item i of state, item i of roundkey)
	end repeat
	
	return new_state
end AddRoundKey

on KeyExpansion(aeskey)
	if class of aeskey is not list or length of aeskey is not 16 then
		error "MixColumns(aeskey): aeskey must be a list of 16 integers"
	end if
	
	local i, i_, new_aeskey, temp
	
	repeat with i in aeskey
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "KeyExpansion(aeskey): integers in aeskey must be in the interval [0, 255]"
		end if
	end repeat
	
	copy aeskey to new_aeskey
	
	repeat with i from (16 + 1) to (16 + 16 * 10) by 4
		if (i - 1) mod 16 is equal to 0 then
			set new_aeskey to new_aeskey & xor(item ((i + 0) - 16) of new_aeskey, xor(subByte(item (i - 3) of new_aeskey), Rcon((i - 1) div 16)))
			set new_aeskey to new_aeskey & xor(item ((i + 1) - 16) of new_aeskey, subByte(item (i - 2) of new_aeskey))
			set new_aeskey to new_aeskey & xor(item ((i + 2) - 16) of new_aeskey, subByte(item (i - 1) of new_aeskey))
			set new_aeskey to new_aeskey & xor(item ((i + 3) - 16) of new_aeskey, subByte(item (i - 4) of new_aeskey))
		else
			set new_aeskey to new_aeskey & xor(item ((i + 0) - 16) of new_aeskey, item ((i + 0) - 4) of new_aeskey)
			set new_aeskey to new_aeskey & xor(item ((i + 1) - 16) of new_aeskey, item ((i + 1) - 4) of new_aeskey)
			set new_aeskey to new_aeskey & xor(item ((i + 2) - 16) of new_aeskey, item ((i + 2) - 4) of new_aeskey)
			set new_aeskey to new_aeskey & xor(item ((i + 3) - 16) of new_aeskey, item ((i + 3) - 4) of new_aeskey)
		end if
	end repeat
	
	return new_aeskey
end KeyExpansion

on MixColumns(state)
	if class of state is not list or length of state is not 16 then
		error "MixColumns(state): state must be a list of 16 integers"
	end if
	
	local i, new_state
	
	repeat with i in state
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "MixColumns(state): integers in state must be in the interval [0, 255]"
		end if
	end repeat
	
	set new_state to {}
	
	repeat with i from 1 to 16 by 4
		set new_state to new_state & xor(xor(galoisMult(item i of state, 2), galoisMult(item (i + 1) of state, 3)), xor(item (i + 2) of state, item (i + 3) of state))
		set new_state to new_state & xor(xor(item i of state, galoisMult(item (i + 1) of state, 2)), xor(galoisMult(item (i + 2) of state, 3), item (i + 3) of state))
		set new_state to new_state & xor(xor(item i of state, item (i + 1) of state), xor(galoisMult(item (i + 2) of state, 2), galoisMult(item (i + 3) of state, 3)))
		set new_state to new_state & xor(xor(galoisMult(item i of state, 3), item (i + 1) of state), xor(item (i + 2) of state, galoisMult(item (i + 3) of state, 2)))
	end repeat
	
	return new_state
end MixColumns

on Rcon(r)
	if class of r is not integer or r is not greater than or equal to 1 or r is not less than or equal to 10 then
		error "rCon(r): r must be an integer in the interval [1, 10]"
	end if
	
	return item r of {1, 2, 4, 8, 16, 32, 64, 128, 27, 54}
end Rcon

on ShiftRows(state)
	if class of state is not list or length of state is not 16 then
		error "ShiftRows(state): state must be a list of 16 integers"
	end if
	
	local i, new_state
	
	repeat with i in state
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "ShiftRows(state): integers in state must be in the interval [0, 255]"
		end if
	end repeat
	
	set new_state to {}
	
	repeat with i in {1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12}
		set new_state to new_state & item i of state
	end repeat
	
	return new_state
end ShiftRows

on subByte(b)
	if class of b is not integer or b is not greater than or equal to 0 or b is not less than or equal to 255 then
		error "subByte(b): b must be an integer in the interval [0, 255]"
	end if
	
	return item (b + 1) of {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22}
end subByte

on SubBytes(state)
	if class of state is not list or length of state is not 16 then
		error "SubBytes(state): state must be a list of 16 integers"
	end if
	
	local i, new_state
	
	repeat with i in state
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "SubBytes(state): integers in state must be in the interval [0, 255]"
		end if
	end repeat
	
	set new_state to {}
	
	repeat with i in state
		set new_state to new_state & subByte(i)
	end repeat
	
	return new_state
end SubBytes

on aes128Encrypt(plaintext, aeskey)
	if class of plaintext is not list or length of plaintext is not 16 or class of aeskey is not list or length of aeskey is not 16 then
		error "aes128Encrypt(plaintext, aeskey): plaintext and aeskey must be a lists of 16 integers"
	end if
	
	local i, roundkey, roundkeys, state1, state2, state3, state4
	
	repeat with i in plaintext
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "aes128Encrypt(plaintext, aeskey): integers in plaintext must be in the interval [0, 255]"
		end if
	end repeat
	
	repeat with i in aeskey
		if class of i is not integer or i is not greater than or equal to 0 or i is not less than or equal to 255 then
			error "aes128Encrypt(plaintext, aeskey): integers in aeskey must be in the interval [0, 255]"
		end if
	end repeat
	
	set roundkeys to KeyExpansion(aeskey)
	
	set roundkey to items 1 through 16 of roundkeys
	set state1 to AddRoundKey(plaintext, items 1 through 16 of roundkeys)
	
	log "Input: " & listToHex(plaintext)
	log "Key: " & listToHex(roundkey)
	log ""
	
	repeat with i from 1 to 10
		log (i as string) & " - Start of Round: " & listToHex(state1)
		
		set state2 to SubBytes(state1)
		
		log (i as string) & " - After SubBytes: " & listToHex(state2)
		
		set state3 to ShiftRows(state2)
		
		log (i as string) & " - After ShiftRows: " & listToHex(state3)
		
		if (i) is less than 10 then
			set state4 to MixColumns(state3)
			
			log (i as string) & " - After MixColumns: " & listToHex(state4)
		else
			copy state3 to state4
		end if
		
		set roundkey to items (16 * i + 1) through (16 * (i + 1)) of roundkeys
		
		log (i as string) & " - Round Key Value: " & listToHex(roundkey)
		
		set state1 to AddRoundKey(state4, roundkey)
	end repeat
	
	log ""
	log "Output: " & listToHex(state1)
end aes128Encrypt

on run argv
	if (count of argv) is 2 and (count of (item 1 of argv)) is 32 and (count of (item 2 of argv)) is 32 then
		aes128Encrypt(hexToList(item 1 of argv), hexToList(item 2 of argv))
	else
		log "Usage: " & (my name) & " plaintext key"
		log ""
		log "'plaintext' and 'key' must each be 32 hexadecimal digits long"
	end if
end run
