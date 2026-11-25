
import math
import string
import secrets


# ==========================================
# PART A: COMMON PASSWORD DATABASE
# ==========================================

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678",
    "12345", "qwerty", "abc123", "password1",
    "admin", "letmein", "welcome", "monkey"
]


# ==========================================
# PART B: PASSWORD ENTROPY
# ==========================================

def calculate_entropy(password):

    charset = 0

    if any(c.islower() for c in password):
        charset += 26

    if any(c.isupper() for c in password):
        charset += 26

    if any(c.isdigit() for c in password):
        charset += 10

    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)

    if any(c.isspace() for c in password):
        charset += 1

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


# ==========================================
# PART C: PATTERN DETECTION
# ==========================================

def has_repeated_pattern(password):

    for i in range(len(password) - 3):

        pattern = password[i:i + 4]

        if len(set(pattern)) == 1:
            return True

    return False


def has_sequence(password):

    sequences = [
        "abcd", "bcde", "cdef", "defg",
        "1234", "2345", "3456", "4567",
        "5678", "6789", "qwer", "asdf", "zxcv"
    ]

    password = password.lower()

    for sequence in sequences:

        if sequence in password:
            return True

    return False


# ==========================================
# PART D: PASSWORD SCORING
# ==========================================

def score_password(password):

    score = 0

    length = len(password)

    entropy = calculate_entropy(password)

    # Length scoring

    if length >= 8:
        score += 15

    if length >= 12:
        score += 15

    # Character variety

    if any(c.islower() for c in password):
        score += 10

    if any(c.isupper() for c in password):
        score += 10

    if any(c.isdigit() for c in password):
        score += 10

    if any(c in string.punctuation for c in password):
        score += 10

    # Entropy scoring

    if entropy > 50:
        score += 20

    # Common password penalty

    if password.lower() in COMMON_PASSWORDS:
        score -= 20

    # Repeated character penalty

    if has_repeated_pattern(password):
        score -= 15

    # Sequential pattern penalty

    if has_sequence(password):
        score -= 15

    # Keep score between 0 and 100

    score = max(0, min(score, 100))

    # Determine strength

    if score < 40:
        strength = "Weak"

    elif score < 60:
        strength = "Moderate"

    elif score < 80:
        strength = "Strong"

    else:
        strength = "Very Strong"

    return {
        "length": length,
        "entropy": entropy,
        "score": score,
        "verdict": strength
    }


# ==========================================
# PART E: PASSWORD GENERATOR
# ==========================================

def generate_password(length=16):

    if length < 12:
        raise ValueError(
            "Password length must be at least 12."
        )

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+"

    # Include at least one character
    # from each category

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    all_characters = (
        lowercase + uppercase + digits + symbols
    )

    for i in range(length - 4):

        password.append(
            secrets.choice(all_characters)
        )

    # Shuffle the characters

    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


# ==========================================
# PART F: PASSWORD ANALYSIS
# ==========================================

def analyze_password():

    password = input("Enter password: ")

    if not password:

        print("Password cannot be empty.")

        return

    result = score_password(password)

    print("\n========== PASSWORD ANALYSIS ==========")

    print(f"Length: {result['length']}")

    print(f"Entropy: {result['entropy']} bits")

    print(f"Score: {result['score']}/100")

    print(f"Verdict: {result['verdict']}")

    # Common password warning

    if password.lower() in COMMON_PASSWORDS:

        print("Warning: Common password detected.")

    # Repeated character warning

    if has_repeated_pattern(password):

        print("Warning: Repeated characters detected.")

    # Sequential pattern warning

    if has_sequence(password):

        print("Warning: Predictable sequence detected.")

    print("======================================")

    # Suggest a stronger password

    if result["verdict"] in ["Weak", "Moderate"]:

        print("\nSuggested stronger password:")

        print(generate_password())


# ==========================================
# PART G: MAIN MENU
# ==========================================

def main():

    print("\n===================================")

    print("    PASSWORD STRENGTH ANALYZER")

    print("===================================")

    while True:

        print("\n1. Analyze Password")

        print("2. Generate Strong Password")

        print("3. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":

            analyze_password()

        elif choice == "2":

            try:

                length = int(
                    input("Enter password length (minimum 12): ")
                )

                password = generate_password(length)

                print("\nGenerated Password:", password)

                result = score_password(password)

                print("Strength:", result["verdict"])

            except ValueError as error:

                print("Invalid input:", error)

        elif choice == "3":

            print("\nThank you for using the analyzer!")

            break

        else:

            print("Invalid choice. Please try again.")


# ==========================================
# PROGRAM EXECUTION
# ==========================================

if __name__ == "__main__":

    main()

