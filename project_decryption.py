import binascii
#STEP 1: ASK FOR THE N
print("-----RSA DECRYPTION-----")
N_receiver = int(input("Enter your N (public key): "))
d = int(input("Enter your d (secret key): "))

def transform_to_hex_decrypt(): #this function gets the plaintext and transform it to hexadecimal and integer
    dec_list = []
    ctr = int(input("How many times will you enter chopped message: "))
    for i in range(ctr):
        cipher = int(input("Enter message here:"))
        decrypt = (square_and_multiply(cipher,d)) #throw this part to decryption
        decrypt_to_hex = hex(decrypt)[2:] #int to hexadecimal
        decrypt_to_ascii = binascii.unhexlify(decrypt_to_hex) #hextostring
        decrypted_final = decrypt_to_ascii.decode()
        dec_list.append(decrypted_final)
        print("Message after decryption: " + str(cipher))
        print("Message in hexadecimal format: " + str(decrypt_to_hex))
        print("Message in ASCII format: " + str(decrypted_final))
    print("This is the decrypted message: " + "".join(dec_list))


def square_and_multiply(base, power): #this function is for square and multiply
    exp = bin(power)
    binary_value = base
    for i in range(3, len(exp)): #3 because when we convert to binary, the first letters are 0b
        binary_value = binary_value * binary_value
        if (exp[i] == '1'):
            binary_value = binary_value * base
            if binary_value > N_receiver:
                binary_value = binary_value % N_receiver
    return binary_value

transform_to_hex_decrypt()