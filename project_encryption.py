import random
import binascii

print("-----RSA ENCRYPTION-----")
print("-----This program will generate your p,q,N,Phi of N,e,d values-----")

def prime_generate_verify(): #this function generates prime numbers p and q
    check = False
    while check == False:
        rnum = random.randint(32768, 65535) #parameters 2^15 as minimum and 2^16 as max
        for number in range(2, rnum - 1): #every number starting from 2 until rnum-1, we check the divisibility
            if rnum % number == 0: #if it divides evenly its not prime
                check = False
                break
            elif rnum % 1 == 0 and rnum % rnum == 0: #double check if the rnum divides to itself and 1 evenly
                check = True
        if rnum % 2 == 0:  # this condition drops every even as a chosen number
            check = False
    return rnum
#STEPS 1,2: GENERATE P,Q, CALCULATE N AND PHI OF N
p = prime_generate_verify()
q = prime_generate_verify()
N = p*q
phi_of_N = (p - 1) * (q - 1)
print("This is your p value: " + str(p))
print("This is your q value: " + str(q))
print("This is your N value (public key): " + str(N))
print("This is your phi of N: " + str(phi_of_N))

#STEP 3: CALCULATE e
possible_e = random.randint(1,phi_of_N-1) #range is from 1 and < phi of N
while possible_e %2 ==0: #redo if even
    possible_e = random.randint(1,phi_of_N-1)
num1 = phi_of_N #putting values in a temp variable
num2 = possible_e #this variables will be used to test the euclidean algorithm

def gcd_verify(num1, num2, possible_e): #this function checks if the possible e is okay to be used as e
    while num2 !=1:
        num1, num2 = num2, num1 % num2  # variable swapping
        if num2 == 0: # I had problems with gcd as 0 so i made this loop
            num1 = phi_of_N
            possible_e = random.randint(1,phi_of_N-1)
            while possible_e % 2 == 0:
                possible_e = random.randint(1, phi_of_N-1)
            num2 = possible_e
            gcd_verify(num1,num2,possible_e)
    return num1,num2,possible_e #this is actually a recursive function but I had to have the possible e return value to make sure its the right one
#CALLING THE FUNCTION FOR E
test1,test2,test_e = gcd_verify(num1,num2,possible_e)
e = test_e
print("This is your e value (public key): " + str(e))

#STEP 4: CALCULATE FOR d
#the multiplicative inverse is based on the Extended Euclid's Algorithm explained at
#https://www.rookieslab.com/posts/how-to-find-multiplicative-inverse-of-a-number-modulo-m-in-python-cpp

def multiplicative_inverse():
    num1 =  phi_of_N
    num2 =  e
    start1 = 0 #the values we used at the start after we finish the gcd
    start2 = 1 #the values we used at the start after we finish the gcd
    while (num1 > 1): #1 will be the end of the equation (as we do on paper) also (x*x(inv)modn=1)
        mod_ans= num1 % num2 #one column for when we answer the mod
        fd_second_col = num1 // num2 #second column where we just get the whole digit
        num1,num2 = num2,mod_ans #variable swapping for the mod and whole digit
        inv_col = start1 - (fd_second_col * start2) #the column where we start with 0 and 1
        start1,start2 = start2,inv_col#variable swapping for the inverse column
    if start1 < 0:
        start1 = start1 % phi_of_N
    return start1
#CALLING THE FUNCTION FOR D
d = multiplicative_inverse()
print("This is your d value (secret key): " + str(d))

#STEP 5: CONVERT THE MESSAGE TO HEXADECIMAL AND THEN TO INT AND ENCRYPT
def transform_to_hex_encrypt(): #this function gets the plaintext and transform it to hexadecimal and integer and then encrypt
    full_message = []
    enc_messages = []
    print("-----ENCRYPTION PART-----")
    receiver_N = int(input("Enter the receiver's N (public key): "))
    receiver_e = int(input("Enter the receiver's e (public key): "))
    ctr = int(input("How many times will you enter chopped message: "))
    for i in range(ctr):
        plain = input("Enter message here:")
        plain_as_bytes = plain.encode()  #string to bytes I used this because it says bytes like objects not str so i added this
        plain_to_hex = binascii.hexlify(plain_as_bytes)  #convert into hexadecimal
        hex_to_int = int(plain_to_hex, 16)#convert our hex into int
        plain_to_cipher = (square_and_multiply(hex_to_int,receiver_e,receiver_N))
        enc_messages.append(plain_to_cipher)
        full_message.append(plain)
        print("Message in hexadecimal form: " + str(plain_to_hex))
        print("Message before Encryption: " + str(hex_to_int))
        print("Above Message in Encrypted format "+str(plain_to_cipher)) #throw this part to encryption
    print("This is the message you've encrypted: " + "".join(full_message))
    print("Message chunks: " + str(full_message))
    print("All the encrypted messages: " + str(enc_messages))


#the square and multiply is based on pseudocode and algorithm explanation of:
# https://asecuritysite.com/encryption/sqm
def square_and_multiply(base, power, receiver_N): #this function is for square and multiply
    exp_as_binary = bin(power) #get the binary form of the exponent
    binary_value = base #varoiable to be tested
    for i in range(3, len(exp_as_binary)): #3 because when we convert to binary, the first letters are 0b
        binary_value = binary_value * binary_value #what happens here is we do every binary but
        if (exp_as_binary[i] == '1'): #this condition will only multiply it to our base if in the binary its value is 1
            binary_value = binary_value * base
            if binary_value > receiver_N: #checks if its greater than our N then it applies mod N
                binary_value = binary_value % receiver_N
    return binary_value


transform_to_hex_encrypt()
