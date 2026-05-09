"""
Standard Finite Field Diffie-Hellman Demo.
Note: A 50-bit prime is used here for demonstration/educational purposes.
"""

import random

# ---------------------------------------------------------------------------
# Diffie-Hellman Parameters
# ---------------------------------------------------------------------------
P = 775145549137931  # The prime modulus
G = 23               # The generator

# P is < 2^56, so 8 bytes is plenty to represent any field element
BYTES = 8


def generate_private_key() -> bytes:
    """Generate a random private key (scalar) between 2 and P-2."""
    # SystemRandom utilizes the OS's cryptographically secure random number generator
    priv = random.SystemRandom().randint(2, P - 2)
    return priv.to_bytes(BYTES, "big")


def public_key(private_key_bytes: bytes) -> bytes:
    """
    Derive the public key from a private key.
    Formula: (G ^ priv) mod P
    """
    priv = int.from_bytes(private_key_bytes, "big")
    pub = pow(G, priv, P)
    return pub.to_bytes(BYTES, "big")


def diffie_hellman(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    Compute the Diffie-Hellman shared secret.
    Formula: (peer_pub ^ priv) mod P
    """
    priv = int.from_bytes(private_key_bytes, "big")
    peer_pub = int.from_bytes(peer_public_key_bytes, "big")
    
    secret = pow(peer_pub, priv, P)
    
    if secret == 1 or secret == 0:
        raise ValueError("Invalid shared secret — peer sent an unsafe public key")
        
    return secret.to_bytes(BYTES, "big")