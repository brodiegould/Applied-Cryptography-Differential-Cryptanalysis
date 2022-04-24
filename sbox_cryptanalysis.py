#!/usr/bin/env python
# coding: utf-8

# In[1]:


# INITIALIZATION
import math
import random


# ### Sbox Implimentation

# In[2]:


# FOR ENCRYPTION - Create dictionary mapping inputs to outputs of sbox of form {input:output}
sboxEncrypt = {'0000':'1110',
               '0001':'0100',
               '0010':'1101',
               '0011':'0001',
               '0100':'0010',
               '0101':'1111',
               '0110':'1011',
               '0111':'1000',
               '1000':'0011',
               '1001':'1010',
               '1010':'0110',
               '1011':'1100',
               '1100':'0101',
               '1101':'1001',
               '1110':'0000',
               '1111':'0111'}
# FOR DECRYPION - Creace dictionary mapping outputs to the inputs of the sbox of form {output:input}
sboxDecrypt = {'1110':'0000',
               '0100':'0001',
               '1101':'0010',
               '0001':'0011',
               '0010':'0100',
               '1111':'0101',
               '1011':'0110',
               '1000':'0111',
               '0011':'1000',
               '1010':'1001',
               '0110':'1010',
               '1100':'1011',
               '0101':'1100',
               '1001':'1101',
               '0000':'1110',
               '0111':'1111'}

# do sbox
def sbox(text):
    
    # test if int
    output_int = 0
    if type(text) == int:
        output_int = 1
        text = "{0:016b}".format(text)
    
    # do sbox mapping
    assert len(text)%4 == 0 #ensure text can be divided into nibbles
    s_text = ''
    for n in range(0,len(text),4):
        if text[n:n+4] in sboxEncrypt:
            s_text += sboxEncrypt[text[n:n+4]]
    
    # output as int if input as int
    if output_int == 1:
        s_text = int(s_text,2)
        
    return s_text


# undo sbox
def sboxInv(text):
    
    # test if int
    output_int = 0
    if type(text) == int:
        output_int = 1
        text = "{0:016b}".format(text)
    
    # do sbox mapping
    assert len(text)%4 == 0
    s_text = ''
    for n in range(0,len(text),4):
        if text[n:n+4] in sboxDecrypt:
            s_text += sboxDecrypt[text[n:n+4]]
    
    # output as int if input as int
    if output_int == 1:
        s_text = int(s_text,2)
    return s_text


# In[3]:


permutation = [1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16]
    
def pbox(text):
    assert len(text) == len(permutation)
    p_text = ''
    for n in permutation:
        p_text += text[n-1]
    return p_text

def keyMix(text, key):
    assert len(text) == len(key)
    x = int(text,2)^int(key,2)
    m_text = format(x, '016b')
    return m_text


# In[4]:


# generate random set of keys for each of the 5 rounds
keySpace = [0, 0, 0, 0, 0]
for i in range(5):
    randNumber = random.randint(0,65535)  # generate random number of 16bits size to populate the value place inside the keyspace dictionary
    randNumber = format(randNumber, '016b')  # convert to binary and add 16bits padding
    keySpace[i] = randNumber

# encryption function
def encrypt(text):
    # round 1
    text = keyMix(text, keySpace[0])
    text = sbox(text)
    text = pbox(text)

    # round 2
    text = keyMix(text, keySpace[1])
    text = sbox(text)
    text = pbox(text)

    # round 3
    text = keyMix(text, keySpace[2])
    text = sbox(text)
    text = pbox(text)

    # round 4
    text = keyMix(text,keySpace[3])
    text = sbox(text)
    text = keyMix(text,keySpace[4])
    
    return text

# decryption function
def decrypt(text):
    # round 4
    text = keyMix(text, keySpace[4])
    text = sboxInv(text)
    text = keyMix(text, keySpace[3])

    # round 3
    text = pbox(text)
    text = sboxInv(text)
    text = keyMix(text, keySpace[2])

    # round 2
    text = pbox(text)
    text = sboxInv(text)
    text = keyMix(text,keySpace[1])

    # round 1
    text = pbox(text)
    text = sboxInv(text)
    text = keyMix(text,keySpace[0])
    
    return text


# In[5]:


# encryption test input
input = 1652
plainText = format(input, '016b')
print(plainText)

cipher = encrypt(plainText)
print(cipher)

message = decrypt(cipher)
print(message)


# ### Difference Distribution Analysis and Testing

# In[6]:


# CREATE DIFFERENCE DISTRIBUTION TABLE FOR MAPPING SBOX

def sbox_diff():
    table = []
    for dX in range(16):
        row = []
        for dY in range(16):
            Y_count = 0
            for X in range(16):
                if sbox(dX^X)^sbox(X) == dY:
                    Y_count += 1
            row.append(Y_count)
        table.append(row)
    return table
    
def sbox_diff_path(in_diff):
    diff_dist_table = sbox_diff()
    max_val = max(diff_dist_table[in_diff])
    count = 0
    for i in diff_dist_table[in_diff]:
        if diff_dist_table[i] == max_val:
            out_diff = i
            count += 1
            if count > 1:
                return -1 #indeterminate
    return out_diff
        

def print_table(table):
    for row in table:
        new_row = ''
        for i in row:
            new_row += "{:<4}".format(i)
        print(new_row)



diff_dist_table = sbox_diff()
print_table(diff_dist_table)


# In[7]:


# HIGH PROBABILITY KEY MAPPINGS WITH PROBABILITIES
sbox_diff_pairs = {'0000':['0000',16],
                   '0010':['0101',6],
                   '0100':['0110',6],
                   '0111':['1111',4],
                   '1001':['0111',4],
                   '1010':['1000',6],
                   '1011':['0010',8],
                   '1100':['1101',6],
                   '1110':['1000',6],
                   '1111':['0100',6]}


# SBOX DIFFERENCE DISTRIBUTION MAPPING
def diff_sbox(text, prob):
    assert len(text) == 16 #ensure text can be divided into nibbles
    s_text = ''
    for n in range(0,16,4):
        if text[n:n+4] in sbox_diff_pairs:
            #use highest probability difference distribution to map sbox input difference to output
            s_text += sbox_diff_pairs[text[n:n+4]][0] 
            prob = prob * (sbox_diff_pairs[text[n:n+4]][1]/16) #add new sbox into total probability
        else:
            return None, None #non-deterministic input
    return s_text, prob


# ENCRYPTION FUNCTION USING DIFFERENCE DISTRIBUTION MAPPED SBOX
def diff_encrypt(text):
    prob = 1
    # round 1
    text, prob = diff_sbox(text, prob)
    if text == None:
        return None, None
    text = pbox(text)

    # round 2
    text, prob = diff_sbox(text, prob)
    if text == None:
        return None, None
    text = pbox(text)

    # round 3
    text, prob = diff_sbox(text, prob)
    if text == None:
        return None, None
    text = pbox(text)

    return text, prob

# FUNCTION TO SHOW SBOX PATH GIVEN DELTA X
def dX_path(text, print_out=1):
    prob = 1
    active_box_list = []
    
    # do 3 rounds
    for i in range(3):
        if print_out: print("\n\nRound {} in:  {}".format(i, text))
        
        # find the active sboxs being used for the round
        round_active_box = [0,0,0,0]
        for n in range(0,16,4):
            if (text[n:n+4] != '0000'):
                round_active_box[int(n/4)] = 1
        active_box_list.append(round_active_box)
        
        # do the difference sbox and pbox for the round
        text, prob = diff_sbox(text, prob)
        if print_out: print("Round {} out: {}".format(i, text))
        if text == None:
            return None, None
        text = pbox(text)
    
    # find the active subkeys for the final output
    round_active_box = [0,0,0,0]
    for n in range(0,16,4):
        if (text[n:n+4] != '0000'):
            round_active_box[int(n/4)] = 1
    active_box_list.append(round_active_box)
    
    # print the final results
    if print_out: 
        print("Final:       ", text)
        print("Prob:  ", prob)
        print(active_box_list)

    return text, active_box_list


# LIST OF POSSIBLE DELTA X INPUTS
def delta_x_list():
    short_list = ['0000','0010','0100','0111','1001','1010','1011','1100','1110','1111']
    output_list = []

    for items1 in short_list:#1*10^3
        for items2 in short_list:#7*10^2
            for items3 in short_list:#1*10
                for items4 in short_list:#1*1
                    test = "%s%s%s%s" % (items1, items2, items3, items4)
                    output_list.append(test)
    return output_list


# LIST OF USEFUL DELTA X INPUTS AND CORRESPONDING SUBKEYS
def output_check(keylist):
    valid_keylist=[]
    for i in range(len(keylist)):
        x, x_prob = diff_encrypt(keylist[i])
        if x != None:
            x_subkey = []
            for n in range(0,16,4):
                if (x[n:n+4] != '0000'):
                    x_subkey.append(int(n/4))
            if len(x_subkey) == 2:
                valid_key = []
                valid_key.extend([x_subkey,keylist[i],x_prob])
                valid_keylist.append(valid_key)

    print('length of the array of valid values is:',len(valid_keylist))
    for i in range(4):
        for j in range(4):
            if i != j:
                max_prob = [[i,j],0,0]
                for item in valid_keylist:
                    if item[0] == [i, j]:
                        if item[2] > max_prob[2]:
                            max_prob = item
                print(max_prob)


                
output_check(delta_x_list())

dX_path('0010001001110010')
dX_path('0111011100101111')
dX_path('0000000011110000')
dX_path('1011000010110000')


# ### Differential Cryptanalysis

# In[8]:


# DIFFERENTIAL ANALYSIS START

# XOR operation of size 4 to handle ΔU, ΔV
def XOR4Block(text1,text2):
    assert len(text1) == 4 and len(text2) ==4
    output= format(int(text1,2)^int(text2,2),'04b')
    return output


#Create 4 global variables to store partial keys of size4 titled keyDiv1,...,4
def splitkeys(key):
    left, right = 0,4
    for idx in range(1,5):
        globals()["keyDiv" + str(idx)] = key[left:right]
        idx += 1
        left += 4
        right += 4
    

#Differential attack for subkeys 2 and 4
def differentialAttack_24(attackedKey):
    assert len(attackedKey) == 16
    count = 0
    total = 0
    splitkeys(attackedKey) #split into 4 variabled keyDiv#
    while (total < 500):
        deltaX = '1011000010110000' #choose desired difference value
        Xp = format(random.randint(0,65535), '016b') #random generated 16 bit #
        Xpp = format(int(Xp,2)^int(deltaX,2),'016b') #XOR X' with ΔX to get X''
        #Run X' X'' pair through SPN cipher
        Yp = encrypt(Xp)
        Ypp = encrypt(Xpp)
        deltaY = format(int(Yp,2)^int(Ypp,2),'016b')
        
        if (deltaY[0:4] !='0000' or deltaY[8:12] !='0000'): #skip input if deltaY doesn't isolate desired subkeys
            total +=1
            continue #end while

        # xor attackedKey with Y then xor attackedKey with deltaY if they are equal then that is a possible key
        # the more times this holds true, the more likely the subkeys are correct
        U2p =     sboxInv(XOR4Block(Yp[4:8],keyDiv2))
        U2pp =    sboxInv(XOR4Block(Ypp[4:8],keyDiv2))
        deltaV2 = XOR4Block(U2p,U2pp)
        U4p =     sboxInv(XOR4Block(Yp[12:16],keyDiv4))
        U4pp =    sboxInv(XOR4Block(Ypp[12:16],keyDiv4))
        deltaV4 = XOR4Block(U4p,U4pp)

        if (deltaV2 == '1000' and deltaV4 == '1000'):
            count +=1
        total +=1
    return count/500


#Differential Attack for subkeys 1 and 3
def differentialAttack_13(attackedKey):
    assert len(attackedKey) == 16
    count = 0
    total = 0
    splitkeys(attackedKey) #split into 4 variabled keyDiv#
    while (total < 100000):
        deltaX = '0111011100101111' #choose desired difference value
        Xp = format(random.randint(0,65535), '016b') #random generated 16 bit #
        Xpp = format(int(Xp,2)^int(deltaX,2),'016b') #XOR X' with ΔX to get X''
        #Run X' X'' pair through SPN cipher
        Yp = encrypt(Xp)
        Ypp = encrypt(Xpp)
        deltaY = format(int(Yp,2)^int(Ypp,2),'016b')
        
        if (deltaY[4:8] !='0000' or deltaY[12:16] !='0000'): #if the ΔY matches the paper with an output on S42 and S44
            total +=1
            continue #end while

        #count each time the ΔU in S42 and S44 match the probabilistic mapping
        U1p =     sboxInv(XOR4Block(Yp[0:4],keyDiv1))
        U1pp =    sboxInv(XOR4Block(Ypp[0:4],keyDiv1))
        deltaV1 = XOR4Block(U1p,U1pp)
        U3p =     sboxInv(XOR4Block(Yp[8:12],keyDiv3))
        U3pp =    sboxInv(XOR4Block(Ypp[8:12],keyDiv3))
        deltaV3 = XOR4Block(U3p,U3pp)
    
        # 0101000010000000
        if (deltaV1 == '0101' and deltaV3 == '1000'):
            count +=1
        total +=1
    return count/100000

print(differentialAttack_24(keySpace[4]))
print(differentialAttack_13(keySpace[4]))
print(differentialAttack_13(format(random.randint(0,65535), '016b')))


# In[9]:


# Perform differential attack on every subkey pair combination to find the maximum probability pair

table_diff = []
# iterate through every key2, key4 combination to perform differential attack on
for i in range(16):
    string_diff1 = "{0:04b}".format(i)
    row_diff = []
    for j in range(16):
        string_diff2 = "{0:04b}".format(j)
        plaintext_diff = '0000'+string_diff1+'0000'+string_diff2
        row_diff.append(differentialAttack_24(plaintext_diff))
    table_diff.append(row_diff) #add result to table so the maximum value can be searched for

# print table
for row in table_diff:
    new_row = ''
    for i in row:
        new_row += "{:<8}".format(i)
    print(new_row)


# In[10]:


# Search table for maximum probability subkey pair
max_probdiff = 0
max_i_diff = -1
max_j_diff = -1
for i in range(16):
     for j in range(16):
        if table_diff[i][j] >= max_probdiff: 
            max_probdiff = table_diff[i][j]
            max_i_diff = i
            max_j_diff = j
print("Probability  subkey2  subkey4")
print("{:^11f}  {:^7d}  {:^7d}".format(max_probdiff, max_i_diff,(max_j_diff)))

print("\n5th round key is:")
print(keySpace[4])
for n in range(0,16,4):
        print("{:^4}".format(int(keySpace[4][n:n+4],2)), end="")
print("\n\nsubkey 2 and 4 match")


# ### General Solution Code (not functioning)

# In[11]:


#Create 4 global variables to store partial keys of size4 titled keyDiv1,...,4
def splitkey(key):
    assert len(key) == 16
    splitkey = []
    for n in range(0,16,4):
        splitkey.append(key[n:n+4])
    return splitkey

def test_subkey_match(key1, key2, test_zeros = False):
    key1 = splitkey(key1)
    key2 = splitkey(key2)
    subkey_match = 0
    
    if test_zeros:
        for i in range(4):
            if (key2[i] == '0000') and (key1[i] == key2[i]):
                subkey_match += 1
    else:
        for i in range(4):
            if (key2[i] != '0000') and (key1[i] == key2[i]):
                subkey_match += 1
                
    if subkey_match == 2:
        return True
    else:
        return False

def differentialAttack(testingKey, deltaX):
    
    assert len(testingKey) == 16
    assert len(deltaX) == 16
    
    # determine which sboxes are active for deltaX and make sure 2 subkeys are being isolated
    target_deltaU, active_box_list = dX_path(deltaX,0)
    assert sum(active_box_list[3]) == 2
    
    count = 0
    total = 0
    while (total < 20):
        X = format(random.randint(0,65535), '016b') #random generated 16 bit #
        Xp = format(int(X,2)^int(deltaX,2),'016b') #XOR X with ΔX to get X'
        
        Y = encrypt(X)
        Yp = encrypt(Xp)
        deltaY = format(int(Y,2)^int(Yp,2),'016b')

        # find the active sboxs being used for the round and remove and deltaY that doesn't match to limit computations
        if (test_subkey_match(deltaY,target_deltaU,test_zeros=True) != True): #skip input if deltaY doesn't isolate desired subkeys
            total +=1
            continue #jump to start of while
        
        # xor attackedKey with Y then xor attackedKey with deltaY if they are equal then that is a possible key
        # the more times this holds true, the more likely the subkeys are correct
        U = sboxInv(int(testingKey,2)^int(Y,2))
        Up = sboxInv(int(testingKey,2)^int(Yp,2))
        deltaU = format(U^Up,'016b')
        if test_subkey_match(deltaU,target_deltaU):
            count += 1
        total += 1
    return count/5000

print(keySpace[4])
#print(test_subkey_match('1011000010110000','0011000000110000', test_zeros = True))
differentialAttack('0001100110101111', '1011000010110000')
#print(splitkey('1011000010110000'))

