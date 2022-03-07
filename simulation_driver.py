import random
from tabulate import tabulate

import encryption as e
import sys

public_key, private_key = e.generate_keypair(16)

columns = 3 # number of candidates
rows = 10 # number of voters

suffix = 0
def gen_voter():
    global suffix
    suffix += 1
    prefix = "Voter "
    return prefix + str(suffix)

def sim_vote():
    global columns
    array = [1 for i in range(columns + 1)]
    array[0] = gen_voter()
    location = random.randint(1,columns)
    array[location] += 1
    return array

# Simulating (plaintext) voting process
data = [sim_vote() for i in range(rows)]
suffix = 0 # Reset suffix for generation of next table

print("\n*** DISCLAIMER ***")
print("Encryption in this demo is done in 16-BIT to allow")
print("for ciphertext to be displayed within their table cells.")
print("ACTUAL ENCRYPTION is done in 128-BIT or higher.")

print("\n[ Legend ]")
print("1 === 'Not-voted-for'")
print("2 === 'Voted-for'")
print("* Values start from '1' as '0' is not eligible for encryption.")
print(tabulate(data, headers = ["Reference Representation", "Candidate Alice", "Candidate Bob", "Candidate Carol"], tablefmt="fancy_grid") + "\n")

candidate1, candidate2, candidate3 = 0, 0, 0
for i in range(len(data)):
    for j in range(len(data[i])):
        if j == 1:
            candidate1 += data[i][j]
        if j == 2:
            candidate2 += data[i][j]
        if j == 3:
            candidate3 += data[i][j]
candidate1 -= rows
candidate2 -= rows
candidate3 -= rows

scores = [["Final votes", candidate1, candidate2, candidate3]]
print(tabulate(scores, headers = ["Tally", "Candidate Alice", "Candidate Bob", "Candidate Carol"]) + "\n")

# Simulating (encrypted) voting process
sample = [["Voter 1"],["Voter 2"]];
for i in range(len(data)):
    for j in range(len(data[i])):
        if j == 1:
            if i == 0:
                sample[0].append(data[i][j])
            if i == 1:
                sample[1].append(data[i][j])
            data[i][j] = e.encrypt(public_key, data[i][j])
            if i == 0:
                sample[0].append(data[i][j])
            if i == 1:
                sample[1].append(data[i][j])
        if j == 2:
            data[i][j] = e.encrypt(public_key, data[i][j])
        if j == 3:
            data[i][j] = e.encrypt(public_key, data[i][j])

# Print actual representation of encrypted values
print("\n" + tabulate(data, headers = ["Actual Representation\n(Values from previous table encrypted)", "Candidate Alice", "Candidate Bob", "Candidate Carol"], tablefmt="fancy_grid") + "\n")

# Print supporting key information
pk = [["Comprises", public_key.n, public_key.g]]
sk = [["Comprises", private_key.gLambda, private_key.gMu]]
print("\n[ Sample ciphertext compuation followed by decryption ]\n")
print(tabulate(pk, headers = ["Public Key", "'n' value", "'g' value"], tablefmt="fancy_grid"))
print(tabulate(sk, headers = ["Private Key", "Lambda value", "Mu value"], tablefmt="fancy_grid") + "\n")
print(tabulate(sample, headers = ["Extract of Both Representations\n(Candidate Alice)", "Plain", "Cipher"], tablefmt="fancy_grid"))

# Print summation process
x = data[0][1] * data[1][1] % public_key.n_sq
print("\n  1. Summing Voter 1 & 2 ciphertext for Candidate Alice\n")
print("        x = (c1 * c2) % Public key n^2\n")
print("             --> (",data[0][1],"*",data[1][1], ") %", public_key.n_sq," =", x, "\n")

# Print decryption process of the summed cipher
y = pow(x, private_key.gLambda, public_key.n_sq) - 1
Message = (((y // public_key.n) * private_key.gMu) % public_key.n) - 2
print("\n  2. Decrypting the summed cipher value & subtracting it by the number of voters (2 in this case)\n")
print("        y = ((x ^ Private key Lambda) % Public key n^2) - 1\n")
print("             --> ((", x, "^", private_key.gLambda, ") %", public_key.n_sq, ") - 1 =", y, "\n\n")
print("        tabulated_votes = (((floor(y / Public key n) * Private key Mu) % Public key n) - Number of voters\n")
print("             --> ((( floor(", y, "/", public_key.n, ") *", private_key.gMu, ") %",public_key.n,") - 2 voters )\n")
print("                  = ", Message, "vote(s)\n")

# Short explanation on final plaintext value
print("                  * Row count (number of voters) is deducted from the")
print("                    decrypted product to reflect the actual votes\n")