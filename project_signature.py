import binascii

print("-----RSA SIGNATURE-----")

def signer():
    enc_sign = []
    sign_list = []
    d_sign_exp = int(input("Enter your d (signing exponent): "))
    N_signer = int(input("Enter your N: "))
    ctr = int(input("How many times will you enter the signature: (Count the spaces, divide your signature in 3 characters): "))
    for i in range(0,ctr):
        plain = input("Enter signature here:")
        sign_list.append(plain)
        print("Current signature: "+"".join(sign_list))
        plain_as_bytes = plain.encode()  # string to bytes I used this because it says bytes like objects not str so i added this
        plain_to_hex = binascii.hexlify(plain_as_bytes)  # convert into hexadecimal
        hex_to_int = int(plain_to_hex, 16)  # convert our hex into int
        encrypted_sign = square_and_multiply(hex_to_int, d_sign_exp, N_signer)
        print("Signature in hexadecimal form: " + str(plain_to_hex))
        print("Signature before Encryption: " + str(hex_to_int))
        print("Above Signature in Encrypted format " + str(encrypted_sign))
        enc_sign.append(encrypted_sign)
    print("Sent this as a verification: " + "".join(sign_list))
    print("All your encrypted signature: " + str(enc_sign))

def verify():
    verify_list = []
    e_ver_exp = int(input("Enter the signer's e (verifying exponent): "))
    N_signer = int(input("Enter the signer's N: "))
    sign_verify = input("Real message: ")
    ctr = int(input("How many times will you enter the signature: "))
    for i in range(ctr):
        sign = int(input("Enter signature here:"))
        decrypt = (square_and_multiply(sign, e_ver_exp, N_signer))  # throw this part to decryption
        decrypt_to_hex = hex(decrypt)[2:]  # int to hexadecimal
        decrypt_to_ascii = binascii.unhexlify(decrypt_to_hex)  # hextostring
        dec_no_b = decrypt_to_ascii.decode()
        verify_list.append(dec_no_b)
        print("Message after decryption: " + str(decrypt))
        print("Message in hexadecimal format: " + str(decrypt_to_hex))
        print("Message in ASCII format: " + str(dec_no_b))
        test_verify = "".join(verify_list)
        is_valid = False
    print("This is the signature: " + test_verify)
    if test_verify == sign_verify:
        is_valid = True
        print(str(is_valid) + " The signature is correct " + test_verify + " and " + sign_verify + " verified.")
    else:
        is_valid = False
        print(str(is_valid) + " The signature is wrong " + test_verify + " and " + sign_verify + " is not valid!" )

def square_and_multiply(base, power, N): #this function is for square and multiply
    exp_as_binary = bin(power) #get the binary form of the exponent
    binary_value = base #variable to be tested
    for i in range(3, len(exp_as_binary)): #3 because when we convert to binary, the first letters are 0b
        binary_value = binary_value * binary_value #what happens here is we do every binary but
        if (exp_as_binary[i] == '1'): #this condition will only multiply it to our base if in the binary its value is 1
            binary_value = binary_value * base
            if binary_value > N: #checks if its greater than our N then it applies mod N
                binary_value = binary_value % N
    return binary_value

choice = input("Do you want to sign or verify? (s for sign and v for verify): ").upper()
if choice == 'S':
    signer()
elif choice == 'V':
    verify()
else:
    print("Not a valid choice")

