import random

# Function for modular exponentiation: (base^exp) % mod
# This is efficient for large numbers using the square-and-multiply method.
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod  # Ensure base is within mod range
    while exp > 0:
        if exp % 2 == 1:  # If exp is odd, multiply the result by the base
            result = (result * base) % mod
        exp = exp >> 1  # Divide exp by 2 (right shift)
        base = (base * base) % mod  # Square the base
    return result

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True  # 2 and 3 are prime
    if n % 2 == 0 or n % 3 == 0:
        return False  # Eliminate multiples of 2 and 3
    i = 5
    # Check divisibility from 5 onwards, skipping even numbers
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Function to find a primitive root for a given prime p
def find_primitive_root(p):
    if not is_prime(p):
        return None  # Return None if p is not prime
    phi = p - 1  # Euler's totient function for p
    factors = prime_factors(phi)  # Get prime factors of phi
    for g in range(2, p):  # Test values from 2 to p-1
        # Check if g is a primitive root
        if all(mod_exp(g, phi // factor, p) != 1 for factor in factors):
            return g
    return None  # No primitive root found

# Function to find all prime factors of a number
def prime_factors(n):
    factors = set()
    while n % 2 == 0:  # Remove all factors of 2
        factors.add(2)
        n //= 2
    for i in range(3, int(n**0.5) + 1, 2):  # Check odd factors
        while n % i == 0:
            factors.add(i)
            n //= i
    if n > 2:  # If n is a prime number greater than 2, add it
        factors.add(n)
    return factors

# Function to generate ElGamal keys
def generate_keys(p, g):
    x = random.randint(2, p - 2)  # Private key x (1 < x < p-1)
    y = mod_exp(g, x, p)  # Public key y = g^x % p
    return {'p': p, 'g': g, 'y': y, 'x': x}

# Function to encrypt a plaintext message using the public key
def encrypt(plaintext, public_key):
    p, g, y = public_key['p'], public_key['g'], public_key['y']
    k = random.randint(2, p - 2)  # Random integer k (1 < k < p-1)
    c1 = mod_exp(g, k, p)  # c1 = g^k % p
    c2 = (plaintext * mod_exp(y, k, p)) % p  # c2 = M * y^k % p
    return (c1, c2)

# Function to decrypt a ciphertext using the private key
def decrypt(ciphertext, private_key):
    c1, c2 = ciphertext
    p, x = private_key['p'], private_key['x']
    s = mod_exp(c1, x, p)  # Compute shared secret s = c1^x % p
    # Decrypted message M = (c2 * s^(-1)) % p using modular inverse of s
    plaintext = (c2 * mod_exp(s, p - 2, p)) % p
    return plaintext

# Main program: Get user input for prime number and primitive root
while True:
    try:
        # Ask user for a prime number
        p = int(input("Enter a prime number (p): "))
        if not is_prime(p):
            print("The number is not prime. Please try again.")
            continue
        # Ask user for a primitive root of the prime
        g = int(input(f"Enter a primitive root of {p} (g): "))
        # Validate if g is a primitive root
        if mod_exp(g, (p - 1) // 2, p) == 1:
            print(f"{g} is not a primitive root of {p}. Please try again.")
            continue
        # Confirm a valid primitive root exists
        if not find_primitive_root(p):
            print(f"Couldn't find a valid primitive root for {p}. Please try again.")
            continue
        break
    except ValueError:
        print("Invalid input. Please enter integers.")

# Generate the public and private keys
keys = generate_keys(p, g)
public_key = {'p': keys['p'], 'g': keys['g'], 'y': keys['y']}
private_key = {'p': keys['p'], 'x': keys['x']}

print("\nGenerated Public Key:", public_key)
print("Generated Private Key:", private_key)

# Encrypt and decrypt an example message
message = int(input("\nEnter the message (as an integer) to encrypt: "))
cipher = encrypt(message, public_key)
print("\nEncrypted Message:", cipher)

# Decrypt and display the original message
decrypted_message = decrypt(cipher, private_key)
print("Decrypted Message:", decrypted_message)
