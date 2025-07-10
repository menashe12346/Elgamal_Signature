# 🔐 ElGamal Signature Scheme (Pure Python)

This project implements the **ElGamal digital signature** scheme from scratch using pure Python – including secure prime generation, subgroup generator selection, keypair generation, signing, and verification.

---

## ✨ Features

- ✅ Cryptographically secure prime generation: `p = 2q + 1`
- ✅ Secure subgroup generator selection in ℤₚ\*
- ✅ Digital signature creation over any message using SHA-256
- ✅ Full signature verification logic
- ✅ User input for subgroup bit-length
- ✅ No external dependencies (only Python standard library)

---

## 📌 How It Works – Step by Step

1. **Subgroup size selection** (bit-length of `q`)
2. **Safe prime generation**:  
   - Generates `q` as a large prime  
   - Computes `p = 2q + 1`  
   - Ensures both `q` and `p` are prime (Sophie-Germain pair)
3. **Generator selection**:  
   - Picks generator `g` such that `g = h^((p-1)/q) mod p`
4. **Keypair generation**:  
   - Private key `x ∈ [2, p-2]`  
   - Public key `y = g^x mod p`
5. **Message signing** using ElGamal algorithm
6. **Signature verification**

---

## 🧪 Example Output

```
Enter bit-length for subgroup order q (e.g., 256): 256
p = 871928593347...
q = 435964296673...
g = 594221207734...
private x = 1234567...
public y = 7890123...
signature = (r, s)
Signature valid? True
```

---

## 📁 File Structure

- `main.py`: Full implementation and demonstration

---

## 🚀 How to Run

```bash
python main.py
```

✅ You’ll be prompted to enter the bit-length of the subgroup order `q`.

---

## 📚 Background

The [ElGamal Signature Scheme](https://en.wikipedia.org/wiki/ElGamal_signature_scheme) is a public-key signature algorithm based on the discrete logarithm problem. It provides **authentication** and **integrity** for digital messages. This implementation follows the standard steps and mathematical rigor using safe primes and subgroup generation.

---
